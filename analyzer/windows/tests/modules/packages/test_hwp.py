import unittest
from unittest.mock import MagicMock, patch

from modules.packages.hwp import HWP


class TestHwp(unittest.TestCase):
    def test_start(self):
        """Test that the start method gets the right parameters."""
        hwp_module = HWP()
        get_path = MagicMock()
        execute = MagicMock()
        # This should not throw a TypeError
        with patch("lib.api.process.Process.execute", execute):
            with patch("modules.packages.hwp.HWP.get_path", get_path):
                hwp_module.start("NUL")
        execute.assert_called_once()
