import argparse
import unittest
from unittest.mock import Mock, patch

from alerts import AlertManager
import main


class AlertManagerTests(unittest.TestCase):
    def test_send_alert_prints_formatted_message(self):
        manager = AlertManager()
        with patch("builtins.print") as print_mock:
            manager.send_alert(
                {
                    "timestamp": "2026-04-22T00:00:00+00:00",
                    "attack_type": "ICMP_FLOOD",
                    "source_ip": "10.10.10.10",
                    "detail": "Observed 100 ICMP packets in 10s",
                }
            )
            print_mock.assert_called_once()
            output = print_mock.call_args[0][0]
            self.assertIn("[ALERT]", output)
            self.assertIn("ICMP_FLOOD", output)
            self.assertIn("src=10.10.10.10", output)

    def test_send_alert_uses_defaults_for_missing_fields(self):
        manager = AlertManager()
        with patch("builtins.print") as print_mock:
            manager.send_alert({})
            output = print_mock.call_args[0][0]
            self.assertIn("unknown-time", output)
            self.assertIn("UNKNOWN", output)
            self.assertIn("unknown-source", output)


class MainModuleTests(unittest.TestCase):
    def test_argument_parser_supports_defaults_and_flags(self):
        parser = main.build_argument_parser()
        self.assertIsInstance(parser, argparse.ArgumentParser)
        defaults = parser.parse_args([])
        self.assertIsNone(defaults.interface)
        self.assertIsNone(defaults.filter)

        parsed = parser.parse_args(["-i", "eth0", "-f", "tcp"])
        self.assertEqual(parsed.interface, "eth0")
        self.assertEqual(parsed.filter, "tcp")

    def test_main_processes_packet_and_exits_cleanly_on_keyboard_interrupt(self):
        detector_instance = Mock()
        detector_instance.process_packet.return_value = [
            {
                "timestamp": "2026-04-22T00:00:00+00:00",
                "attack_type": "PORT_SCAN",
                "source_ip": "1.2.3.4",
                "detail": "details",
            }
        ]
        alerts_instance = Mock()
        logger_instance = Mock()

        class FakePacketSniffer:
            created = None

            def __init__(self, packet_handler, interface=None, bpf_filter=None):
                self.packet_handler = packet_handler
                self.interface = interface
                self.bpf_filter = bpf_filter
                self.stopped = False
                FakePacketSniffer.created = self

            def start(self):
                self.packet_handler(object())

            def stop(self):
                self.stopped = True

        with (
            patch.object(main, "Detector", return_value=detector_instance),
            patch.object(main, "AlertManager", return_value=alerts_instance),
            patch.object(main, "EventLogger", return_value=logger_instance),
            patch.object(main, "PacketSniffer", FakePacketSniffer),
            patch.object(main, "extract_packet_features", return_value={"timestamp": 1, "src_ip": "1.2.3.4"}),
            patch.object(main.time, "sleep", side_effect=KeyboardInterrupt),
            patch("sys.argv", ["main.py", "-i", "eth0", "-f", "tcp"]),
        ):
            result = main.main()

        self.assertEqual(result, 0)
        detector_instance.process_packet.assert_called_once()
        alerts_instance.send_alert.assert_called_once()
        logger_instance.log_event.assert_called_once()
        self.assertTrue(FakePacketSniffer.created.stopped)
        self.assertEqual(FakePacketSniffer.created.interface, "eth0")
        self.assertEqual(FakePacketSniffer.created.bpf_filter, "tcp")

    def test_main_returns_error_when_sniffer_start_fails(self):
        detector_instance = Mock()
        detector_instance.process_packet.return_value = []
        alerts_instance = Mock()
        logger_instance = Mock()
        sniffer_instance = Mock()
        sniffer_instance.start.side_effect = RuntimeError("boom")

        with (
            patch.object(main, "Detector", return_value=detector_instance),
            patch.object(main, "AlertManager", return_value=alerts_instance),
            patch.object(main, "EventLogger", return_value=logger_instance),
            patch.object(main, "PacketSniffer", return_value=sniffer_instance),
            patch("sys.argv", ["main.py"]),
        ):
            result = main.main()

        self.assertEqual(result, 1)
        sniffer_instance.stop.assert_called_once()

    def test_main_ignores_packets_when_feature_extraction_returns_none(self):
        detector_instance = Mock()
        alerts_instance = Mock()
        logger_instance = Mock()

        class FakePacketSniffer:
            def __init__(self, packet_handler, interface=None, bpf_filter=None):
                self.packet_handler = packet_handler

            def start(self):
                self.packet_handler(object())

            def stop(self):
                pass

        with (
            patch.object(main, "Detector", return_value=detector_instance),
            patch.object(main, "AlertManager", return_value=alerts_instance),
            patch.object(main, "EventLogger", return_value=logger_instance),
            patch.object(main, "PacketSniffer", FakePacketSniffer),
            patch.object(main, "extract_packet_features", return_value=None),
            patch.object(main.time, "sleep", side_effect=KeyboardInterrupt),
            patch("sys.argv", ["main.py"]),
        ):
            result = main.main()

        self.assertEqual(result, 0)
        detector_instance.process_packet.assert_not_called()
        alerts_instance.send_alert.assert_not_called()
        logger_instance.log_event.assert_not_called()


if __name__ == "__main__":
    unittest.main()
