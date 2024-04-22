import random
import unittest
from unittest.mock import MagicMock, patch

import analyzer
from analyzer import Analyzer, CommandPipeHandler


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.patches = []
        patch_sleep = patch("lib.common.defines.KERNEL32.Sleep")
        self.patches.append(patch_sleep)
        patch_call = patch("subprocess.call")
        self.patches.append(patch_call)
        for p in self.patches:
            self.addCleanup(p.stop)
            p.start()
        self.analyzer = Analyzer()
        self.cph = CommandPipeHandler(self.analyzer)

    def test_can_instantiate(self):
        self.assertIsInstance(self.analyzer, Analyzer)
        self.assertIsInstance(self.cph, CommandPipeHandler)

    def test_get_pipe_path(self):
        pipe_name = "random_text"
        pipe_path = self.analyzer.get_pipe_path(pipe_name)
        self.assertIsNotNone(pipe_path)
        self.assertIsInstance(pipe_path, str)
        self.assertIn(pipe_name, pipe_path)
        self.assertIn("PIPE", pipe_path)

    @patch("analyzer.pid_from_service_name")
    @patch("analyzer.Process")
    def test_handle_interop(self, mock_process, mock_pid_from_service_name):
        mock_process.return_value = MagicMock()
        random_pid = random.randint(1, 99999999)
        mock_pid_from_service_name.return_value = random_pid
        ana = self.analyzer
        # instead of mocking Process mock Process.get_filepath and Process.open maybe
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_interop(None)
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
        mock_pid_from_service_name.assert_called_once()

    @patch("analyzer.Process")
    def test_handle_interop_already(self, mock_process):
        """If dcom process already monitored, do nothing."""
        ana = self.analyzer
        ana.MONITORED_DCOM = True
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.cph._handle_interop(None)
        # No change to process list or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    def test_handle_wmi(self, mock_pid_from_service_name):
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        mock_pid_from_service_name.side_effect = [random_pid1, random_pid2]
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_WMI)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_wmi(None)
        self.assertEqual(2, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_WMI)
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.assertIn(random_pid1, ana.CRITICAL_PROCESS_LIST)
        self.assertIn(random_pid2, ana.CRITICAL_PROCESS_LIST)

    @patch("analyzer.pid_from_service_name")
    def test_handle_wmi_already(self, mock_pid_from_service_name):
        ana = self.analyzer
        ana.MONITORED_WMI = True
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_wmi(None)
        # Should be no change to DCOM or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_pid_from_service_name.assert_not_called()

    def test_handle_wmi_timed_out(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_WMI)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        analyzer.ANALYSIS_TIMED_OUT = True
        self.cph._handle_bits(data=None)
        # Should be no change to DCOM, WMI, or last inject time
        self.assertFalse(ana.MONITORED_WMI)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        # put back the default value
        analyzer.ANALYSIS_TIMED_OUT = False

    @patch("analyzer.pid_from_service_name")
    def test_handle_bits(self, mock_pid_from_service_name):
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        mock_pid_from_service_name.side_effect = [random_pid1, random_pid2]
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_BITS)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_bits(data=None)
        self.assertEqual(2, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_BITS)
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)

    def test_handle_bits_already(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        ana.MONITORED_BITS = True
        self.cph._handle_bits(data=None)
        # Should be no change to DCOM or last inject time
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)

    def test_handle_bits_timed_out(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_BITS)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        analyzer.ANALYSIS_TIMED_OUT = True
        self.cph._handle_bits(data=None)
        # Should be no change to DCOM, BITS, or last inject time
        self.assertFalse(ana.MONITORED_BITS)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        # put back the default value
        analyzer.ANALYSIS_TIMED_OUT = False
