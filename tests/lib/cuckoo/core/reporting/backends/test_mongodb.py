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
from lib.cuckoo.core.reporting import api
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

    def test_nonexistent_task_summary(self):
        """Ask for a task that is not present in the MongoDB."""
        mongo = mongodb.MongoDBReports(config.Config("reporting"))
        task_id = random.randint(0, 100000)
        result = mongo.summary(task_id)
        assert result is None
