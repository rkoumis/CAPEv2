import datetime
import functools
import inspect
import pathlib
import random
from unittest import mock

import mongomock
import pymongo
import pytest

from lib.cuckoo.common import config
from lib.cuckoo.common.config import ConfigMeta
from lib.cuckoo.core.reporting import api, schema
from lib.cuckoo.core.reporting.backends import mongodb

TEST_DB_NAME = "cuckoo_test_db"
TEST_COLLECTION_NAME = "cuckoo_test_collection"

getfunctions = functools.partial(inspect.getmembers, predicate=inspect.isfunction)


@pytest.fixture
def mongodb_enabled(custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "reporting.conf", "wt") as fil:
        print(f"[mongodb]\nenabled = yes\ndb = {TEST_DB_NAME}", file=fil)
    ConfigMeta.refresh()
    yield


@pytest.fixture
def mongodb_mock_client(request):
    with mongomock.patch(servers=(("127.0.0.1", 27017),)):
        client = pymongo.MongoClient(host=f"mongodb://127.0.0.1/{TEST_DB_NAME}")
        request.instance.mongo_client = client
        with mock.patch("dev_utils.mongodb.conn", new=client):
            yield


@pytest.mark.usefixtures("mongodb_enabled", "mongodb_mock_client")
class TestMongoDBReportingBackend:
    def test_has_api_methods(self):
        api_functions = {x for x in getfunctions(api.Reports)}
        assert len(api_functions) > 0
        backend = mongodb.MongoDBReports
        for fn in api_functions:
            assert hasattr(backend, fn[0])
            msg = f"reporting backend {backend} does not implement '{fn[0]}'"
            assert getattr(backend, fn[0]) != fn[1], msg

    def test_initialize(self):
        """Test that we can initialize a MongoDBReports instance."""
        mongo = mongodb.MongoDBReports(config.Config("reporting"))
        assert isinstance(mongo, mongodb.MongoDBReports)
        assert isinstance(mongo._client, mongomock.MongoClient)
        assert mongo._client.host == "127.0.0.1"

    def test_nonexistent_summary(self):
        """Ask for a summary that is not present in the MongoDB."""
        mongo = mongodb.MongoDBReports(config.Config("reporting"))
        task_id = random.randint(0, 100000)
        result = mongo.summary(task_id)
        assert result is None

    def test_summary(self):
        """Retrieve a Summary from MongoDB."""
        mongo = mongodb.MongoDBReports(config.Config("reporting"))
        task_id = random.randint(0, 100000)
        machine = {
            "id": 28033,
            "status": "stopping",
            "name": "windows-machine-1",
            "label": "windows-machine-label",
            "platform": "windows",
            "manager": "KVM",
            "started_on": "2024-03-29 14:00:26",
            "shutdown_on": "2024-03-29 14:04:20",
        }
        info = {
            "id": task_id,
            "machine": machine,
        }
        analysis = {
            "info": info,
            "target": {
                "file": {
                    "virustotal": {
                        "summary": "66/76",
                    },
                    "clamav": [],
                },
            },
            "url": {
                "virustotal": {
                    "summary": "20/30",
                }
            },
            "detections": [
                {
                    "family": "Robinson",
                    "details": [
                        {"VirusTotal": "bbbbbbbbbbbbbbbbbbbb"},
                    ],
                }
            ],
            "suri_tls_cnt": 6,
            "suri_alert_cnt": 17,
            "suri_http_cnt": 210,
            "trid": 17,
            "ensure_extra_fields": "are_allowed",
        }
        database = self.mongo_client[TEST_DB_NAME]
        analysis_coll = database[mongodb._analysis_coll]
        analysis_coll.insert_one(analysis)
        result = mongo.summary(task_id)
        assert isinstance(result, schema.Summary)
        assert result.trid == 17
        assert result.suri_http_cnt == 210
        assert result.info.machine.name == "windows-machine-1"
        assert isinstance(result.info.machine.started_on, datetime.datetime)
        assert str(result.info.machine.started_on) == "2024-03-29 14:00:26"
        assert result.vt_file_summary == "66/76"
        assert result.vt_url_summary == "20/30"
        assert result.clamav == []
