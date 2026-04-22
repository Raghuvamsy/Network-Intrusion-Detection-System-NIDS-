import unittest

from config import NIDSConfig
from detector import Detector


class DetectorTests(unittest.TestCase):
    def test_process_packet_ignores_missing_source(self):
        detector = Detector()
        self.assertEqual(detector.process_packet({}), [])
        self.assertEqual(detector.process_packet({"protocol": "TCP"}), [])

    def test_port_scan_detects_and_throttles_then_realerts(self):
        config = NIDSConfig(port_scan_threshold=3, syn_flood_threshold=999, icmp_flood_threshold=999)
        detector = Detector(config=config)
        src = "10.0.0.1"

        self.assertEqual(
            detector.process_packet({"timestamp": 11, "src_ip": src, "dst_port": 80}),
            [],
        )
        self.assertEqual(
            detector.process_packet({"timestamp": 12, "src_ip": src, "dst_port": 81}),
            [],
        )
        alerts = detector.process_packet({"timestamp": 13, "src_ip": src, "dst_port": 82})
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attack_type"], "PORT_SCAN")

        throttled = detector.process_packet({"timestamp": 14, "src_ip": src, "dst_port": 83})
        self.assertEqual(throttled, [])

        detector.process_packet({"timestamp": 24, "src_ip": src, "dst_port": 84})
        detector.process_packet({"timestamp": 25, "src_ip": src, "dst_port": 85})
        alerted_again = detector.process_packet({"timestamp": 26, "src_ip": src, "dst_port": 86})
        self.assertEqual(len(alerted_again), 1)
        self.assertEqual(alerted_again[0]["attack_type"], "PORT_SCAN")

    def test_syn_flood_detects_and_ack_clears_pending(self):
        config = NIDSConfig(port_scan_threshold=999, syn_flood_threshold=2, icmp_flood_threshold=999)
        detector = Detector(config=config)
        attacker = "192.168.1.10"
        target = "192.168.1.20"

        detector.process_packet(
            {
                "timestamp": 11,
                "src_ip": attacker,
                "dst_ip": target,
                "protocol": "TCP",
                "src_port": 1111,
                "dst_port": 80,
                "tcp_flags": "S",
            }
        )
        alerts = detector.process_packet(
            {
                "timestamp": 12,
                "src_ip": attacker,
                "dst_ip": target,
                "protocol": "TCP",
                "src_port": 1112,
                "dst_port": 80,
                "tcp_flags": "S",
            }
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attack_type"], "SYN_FLOOD")

        detector.process_packet(
            {
                "timestamp": 13,
                "src_ip": target,
                "dst_ip": attacker,
                "protocol": "TCP",
                "src_port": 80,
                "dst_port": 1111,
                "tcp_flags": "SA",
            }
        )
        self.assertEqual(len(detector._incomplete_handshakes[attacker]), 1)

    def test_icmp_flood_detects(self):
        config = NIDSConfig(port_scan_threshold=999, syn_flood_threshold=999, icmp_flood_threshold=3)
        detector = Detector(config=config)
        src = "172.16.0.5"

        detector.process_packet({"timestamp": 11, "src_ip": src, "protocol": "ICMP"})
        detector.process_packet({"timestamp": 12, "src_ip": src, "protocol": "ICMP"})
        alerts = detector.process_packet({"timestamp": 13, "src_ip": src, "protocol": "ICMP"})

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attack_type"], "ICMP_FLOOD")

    def test_old_activity_is_trimmed_by_time_window(self):
        config = NIDSConfig(port_scan_threshold=2, syn_flood_threshold=999, icmp_flood_threshold=999, time_window_seconds=5)
        detector = Detector(config=config)
        src = "8.8.8.8"

        detector.process_packet({"timestamp": 1, "src_ip": src, "dst_port": 1000})
        alerts = detector.process_packet({"timestamp": 7, "src_ip": src, "dst_port": 1001})
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
