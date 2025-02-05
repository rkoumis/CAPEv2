"""Tests for dev_utils/mongodb.py.

Use sys.modules.pop() to cause python to freshly import dev_utils.mongodb as if
for the first time.
"""
import pathlib
import sys
import unittest
from unittest import mock
from unittest.mock import MagicMock

import pytest
from pymongo import MongoClient
from pymongo.database import Database

from lib.cuckoo.common.config import ConfigMeta

TEST_DB_NAME = "cuckoo_test_db"
TEST_COLLECTION_NAME = "cuckoo_test_collection"


@pytest.fixture
def mongodb_enabled(custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "reporting.conf", "wt") as fil:
        print(f"[mongodb]\nenabled = yes\ndb = {TEST_DB_NAME}", file=fil)
    ConfigMeta.refresh()
    yield


@pytest.mark.usefixtures("mongodb_enabled")
class TestMongoDB(unittest.TestCase):
    def setUp(self):
        """Un-import the dev_utils.mongodb module."""
        sys.modules.pop("dev_utils.mongodb", None)

    def tearDown(self):
        """Again, un-import the dev_utils.mongodb module."""
        sys.modules.pop("dev_utils.mongodb", None)

    def test_connect_to_mongo(self):
        """Test that we can create a connection to a MongoDB instance"""
        import dev_utils.mongodb

        self.assertIsNone(dev_utils.mongodb.conn)
        self.assertIsNone(dev_utils.mongodb.mdb)

        client = dev_utils.mongodb.connect_to_mongo()
        self.assertIsInstance(client, MongoClient)
        the_db = client[TEST_DB_NAME]
        self.assertIsNotNone(the_db)
        self.assertIsInstance(the_db, Database)
        self.assertEqual(TEST_DB_NAME, dev_utils.mongodb.mdb)

    def test_get_results_db(self):
        """Test the get_results_db method."""
        import dev_utils.mongodb

        called = False
        mock_db = MagicMock()
        self.assertIsNone(dev_utils.mongodb.conn)
        self.assertIsNone(dev_utils.mongodb.mdb)

        def mock_init_mongo():
            nonlocal called
            called = True
            dev_utils.mongodb.mdb = TEST_DB_NAME
            dev_utils.mongodb.conn = {TEST_DB_NAME: mock_db}

        with mock.patch("dev_utils.mongodb.init_mongo", new_callable=mock_init_mongo):
            actual_db = dev_utils.mongodb.get_results_db()
            self.assertIs(actual_db, mock_db)
            self.assertTrue(called)

        # Call get_results_db() again; it should not call init_mongo this time.
        with mock.patch("dev_utils.mongodb.init_mongo", new_callable=mock_init_mongo):
            called = False
            actual_db = dev_utils.mongodb.get_results_db()
            self.assertIs(actual_db, mock_db)
            self.assertFalse(called)

    def test_init_mongo(self):
        """Test the init_mongo method."""
        import dev_utils.mongodb

        self.assertIsNone(dev_utils.mongodb.conn)
        self.assertIsNone(dev_utils.mongodb.mdb)

        with mock.patch("dev_utils.mongodb.connect_to_mongo") as mock_connect_to_mongo:
            dev_utils.mongodb.init_mongo()
            mock_connect_to_mongo.assert_called_once()
            self.assertIsInstance(dev_utils.mongodb.conn, MagicMock)
            # Call init_mongo again; connect_to_mongo should not be called again.
            dev_utils.mongodb.init_mongo()
            mock_connect_to_mongo.assert_called_once()
