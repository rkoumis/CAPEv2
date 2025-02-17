import pathlib
import random
import sys
from unittest import mock
from unittest.mock import patch

import bson
import mongomock
import pymongo
import pytest

from lib.cuckoo.common.config import ConfigMeta
from modules.reporting.mongodb_constants import CALLS_COLL

TEST_DB_NAME = "cuckoo_test"


@pytest.fixture
def mongodb_enabled(custom_conf_path: pathlib.Path):
    """Enable mongodb.

    Use sys.modules.pop to ensure target gets imported
    as if for the first time.
    """
    with open(custom_conf_path / "reporting.conf", "wt") as fil:
        print(f"[mongodb]\nenabled = yes\ndb = {TEST_DB_NAME}", file=fil)
    ConfigMeta.refresh()
    sys.modules.pop("modules.reporting.report_doc", None)
    yield
    # Pop the module again, to reset the state for other tests.
    sys.modules.pop("modules.reporting.report_doc", None)


@pytest.fixture
def mongodb_mock_client(request):
    with mongomock.patch(servers=(("127.0.0.1", 27017),)):
        client = pymongo.MongoClient(host=f"mongodb://127.0.0.1/{TEST_DB_NAME}")
        request.instance.mongo_client = client
        with mock.patch("dev_utils.mongodb.conn", new=client):
            yield


@pytest.mark.usefixtures("mongodb_enabled", "db", "mongodb_mock_client")
class TestReportDoc:
    def test_insert_calls_mongodb(self):
        """Test the insert_calls function."""
        from modules.reporting.report_doc import insert_calls

        pid0, pid1 = random.randint(1, 1000), random.randint(1, 1000)
        report = {
            "behavior": {
                "processes": [
                    {
                        "process_id": pid0,
                        "calls": [
                            {
                                "timestamp": "2025-01-01 01:01:01",
                            },
                        ],
                    },
                    {
                        "process_id": pid1,
                        "calls": [
                            {
                                "timestamp": "2025-02-02 02:02:02",
                            },
                        ],
                    },
                ]
            }
        }
        with patch("modules.reporting.report_doc.CHUNK_CALL_SIZE", new=1):
            result = insert_calls(report, mongodb=True)
            assert isinstance(result, list)
            assert result[0]["process_id"] == pid0
            assert result[1]["process_id"] == pid1
            expected_calls = [
                result[0]["calls"][0],
                result[1]["calls"][0],
            ]
            collection = self.mongo_client[TEST_DB_NAME][CALLS_COLL]
            for item in expected_calls:
                assert isinstance(item, bson.objectid.ObjectId)
                obj = collection.find_one({"_id": item})
                assert obj is not None
