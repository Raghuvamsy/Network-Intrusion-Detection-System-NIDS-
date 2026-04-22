import unittest
from unittest.mock import Mock, patch

import sniffer
from sniffer import PacketSniffer


class _FakeAsyncSniffer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class _FailingStopSniffer:
    def stop(self):
        raise RuntimeError("stop failed")


class PacketSnifferTests(unittest.TestCase):
    def test_start_raises_helpful_error_when_scapy_is_missing(self):
        snf = PacketSniffer(packet_handler=lambda _: None)
        with patch.object(sniffer, "AsyncSniffer", None):
            with self.assertRaises(RuntimeError):
                snf.start()

    def test_start_creates_async_sniffer_with_expected_arguments(self):
        snf = PacketSniffer(packet_handler=lambda _: None, interface="eth0", bpf_filter="tcp")
        with patch.object(sniffer, "AsyncSniffer", _FakeAsyncSniffer):
            snf.start()
            self.assertIsNotNone(snf._sniffer)
            self.assertTrue(snf._sniffer.started)
            self.assertEqual(snf._sniffer.kwargs["iface"], "eth0")
            self.assertEqual(snf._sniffer.kwargs["filter"], "tcp")
            self.assertFalse(snf._sniffer.kwargs["store"])

    def test_stop_is_safe_when_not_started(self):
        snf = PacketSniffer(packet_handler=lambda _: None)
        snf.stop()
        self.assertIsNone(snf._sniffer)

    def test_stop_swallows_sniffer_stop_errors_and_clears_state(self):
        snf = PacketSniffer(packet_handler=lambda _: None)
        snf._sniffer = _FailingStopSniffer()
        snf.stop()
        self.assertIsNone(snf._sniffer)

    def test_safe_handler_catches_callback_errors(self):
        handler = Mock(side_effect=ValueError("bad packet"))
        snf = PacketSniffer(packet_handler=handler)
        with patch("builtins.print") as print_mock:
            snf._safe_handler(object())
            handler.assert_called_once()
            print_mock.assert_called_once()
            self.assertIn("[SNIFFER_ERROR] packet handling failed", print_mock.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
