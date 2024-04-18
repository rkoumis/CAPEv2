import unittest

from analyzer import Analyzer


class TestAnalyzer(unittest.TestCase):
    def test_can_instantiate(self):
        analyzer = Analyzer()
        self.assertIsInstance(analyzer, Analyzer)

    def test_monitor_dcom(self):
        analyzer = Analyzer()
        self.assertEqual(0, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertFalse(analyzer.MONITORED_DCOM)
        self.assertIsNone(analyzer.LASTINJECT_TIME)
        analyzer.monitor_dcom()
        self.assertEqual(1, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertTrue(analyzer.MONITORED_DCOM)
        self.assertIsNotNone(analyzer.LASTINJECT_TIME)

    def test_monitor_wmi(self):
        analyzer = Analyzer()
        self.assertEqual(0, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertFalse(analyzer.MONITORED_WMI)
        self.assertIsNone(analyzer.LASTINJECT_TIME)
        analyzer.monitor_wmi()
        self.assertEqual(1, len(analyzer.CRITICAL_PROCESS_LIST))
        self.assertTrue(analyzer.MONITORED_WMI)
        self.assertIsNotNone(analyzer.LASTINJECT_TIME)
