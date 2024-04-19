import unittest

from analyzer import Files


class TestFiles(unittest.TestCase):
    def test_can_instantiate(self):
        files = Files()
        self.assertIsInstance(files, Files)

    def test_is_protected_filename(self):
        files = Files()
        not_protected = "not_protected"
        self.assertFalse(files.is_protected_filename(not_protected))
        should_be_protected = "PYTHON.EXE"
        self.assertTrue(files.is_protected_filename(should_be_protected))

    def test_is_protected_filename_class_method(self):
        not_protected = "not_protected"
        self.assertFalse(Files.is_protected_filename(not_protected))
        should_be_protected = "PYTHON.EXE"
        self.assertTrue(Files.is_protected_filename(should_be_protected))
