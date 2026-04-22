import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import NIDSConfig
from logger import EventLogger


class _FailingPath:
    def open(self, *args, **kwargs):
        raise OSError("simulated-failure")


class EventLoggerTests(unittest.TestCase):
    def test_logger_creates_csv_header_on_first_run(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = NIDSConfig(log_directory=tmp_dir)
            EventLogger(config=config)

            csv_path = Path(tmp_dir) / config.csv_log_file
            content = csv_path.read_text(encoding="utf-8").strip()
            self.assertEqual(content, "timestamp,attack_type,source_ip,detail")

    def test_log_event_writes_jsonl_and_csv(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = NIDSConfig(log_directory=tmp_dir)
            logger = EventLogger(config=config)

            event = {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "attack_type": "PORT_SCAN",
                "source_ip": "10.0.0.5",
                "detail": "Observed many ports",
            }
            logger.log_event(event)

            json_path = Path(tmp_dir) / config.json_log_file
            csv_path = Path(tmp_dir) / config.csv_log_file

            json_line = json_path.read_text(encoding="utf-8").strip().splitlines()[-1]
            self.assertEqual(json.loads(json_line), event)

            csv_lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(csv_lines), 2)
            self.assertIn("PORT_SCAN", csv_lines[-1])

    def test_log_event_normalizes_missing_fields_to_empty_strings(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = NIDSConfig(log_directory=tmp_dir)
            logger = EventLogger(config=config)

            logger.log_event({"attack_type": "ICMP_FLOOD"})

            json_path = Path(tmp_dir) / config.json_log_file
            json_line = json_path.read_text(encoding="utf-8").strip().splitlines()[-1]
            payload = json.loads(json_line)
            self.assertEqual(payload["attack_type"], "ICMP_FLOOD")
            self.assertEqual(payload["timestamp"], "")
            self.assertEqual(payload["source_ip"], "")
            self.assertEqual(payload["detail"], "")

    def test_write_json_handles_oserror_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = EventLogger(config=NIDSConfig(log_directory=tmp_dir))
            logger.json_path = _FailingPath()

            with patch("builtins.print") as print_mock:
                logger._write_json({"attack_type": "x"})
                print_mock.assert_called_once()
                self.assertIn("[LOGGER_ERROR] failed to write JSON log", print_mock.call_args[0][0])

    def test_write_csv_handles_oserror_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = EventLogger(config=NIDSConfig(log_directory=tmp_dir))
            logger.csv_path = _FailingPath()

            with patch("builtins.print") as print_mock:
                logger._write_csv({"attack_type": "x"})
                print_mock.assert_called_once()
                self.assertIn("[LOGGER_ERROR] failed to write CSV log", print_mock.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
