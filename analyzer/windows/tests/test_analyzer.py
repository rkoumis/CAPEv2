import unittest
from unittest.mock import MagicMock, patch

from analyzer import Analyzer, CommandPipeHandler


class TestAnalyzer(unittest.TestCase):
    def test_can_instantiate(self):
        analyzer = Analyzer()
        self.assertIsInstance(analyzer, Analyzer)

    @patch("pid_from_service_name")
    @patch("lib.api.process.Process")
    def test_monitor_dcom(self, mock_process, mock_pid_from_service_name):
        mock_process.return_value = MagicMock()
        mock_pid_from_service_name.return_value = 100
        analyzer = Analyzer()
        self.assertEqual(0, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertFalse(analyzer.MONITORED_DCOM)
        self.assertIsNone(analyzer.LASTINJECT_TIME)
        analyzer.monitor_dcom()
        self.assertEqual(1, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertTrue(analyzer.MONITORED_DCOM)
        self.assertIsNotNone(analyzer.LASTINJECT_TIME)
        self.assertIn(100, analyzer.CRITICAL_PROCESS_LIST)

    def test_monitor_wmi(self):
        analyzer = Analyzer()
        self.assertEqual(0, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertFalse(analyzer.MONITORED_WMI)
        self.assertIsNone(analyzer.LASTINJECT_TIME)
        analyzer.monitor_wmi()
        self.assertEqual(1, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertTrue(analyzer.MONITORED_WMI)
        self.assertIsNotNone(analyzer.LASTINJECT_TIME)

    def test_get_pipe_path(self):
        pipe_name = "random_text"
        pipe_path = Analyzer.get_pipe_path(pipe_name)
        self.assertIsNotNone(pipe_path)
        self.assertIsInstance(pipe_path, str)
        self.assertIn(pipe_name, pipe_path)
        self.assertIn("PIPE", pipe_path)

    def test_handle_bits(self):
        analyzer = Analyzer()
        cph = CommandPipeHandler(analyzer)
        self.assertEqual(0, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertFalse(analyzer.MONITORED_DCOM)
        self.assertIsNone(analyzer.LASTINJECT_TIME)
        cph._handle_bits(data=None)
        self.assertEqual(2, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertTrue(analyzer.MONITORED_DCOM)
        self.assertIsNotNone(analyzer.LASTINJECT_TIME)
