import datetime
import functools
import inspect
import random

import mongomock
import pytest

from .conftest import TEST_TASK_ID, TEST_PIDS
from lib.cuckoo.core.reporting import api, schema
from lib.cuckoo.core.reporting.backends import mongodb

getfunctions = functools.partial(inspect.getmembers, predicate=inspect.isfunction)


@pytest.mark.usefixtures("mongodb_config", "mongodb_mock_client")
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
        mongo = mongodb.MongoDBReports(self.cfg)
        assert isinstance(mongo, mongodb.MongoDBReports)
        assert isinstance(mongo._client, mongomock.MongoClient)
        assert mongo._client.host == "127.0.0.1"

    def test_nonexistent_summary(self):
        """Ask for a summary that is not present in the MongoDB."""
        mongo = mongodb.MongoDBReports(self.cfg)
        task_id = random.randint(0, 100000)
        result = mongo.summary(task_id)
        assert result is None

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_summary(self):
        """Retrieve a Summary from MongoDB."""
        mongo = mongodb.MongoDBReports(self.cfg)
        result = mongo.summary(TEST_TASK_ID)
        assert isinstance(result, schema.Summary)
        assert result.trid == 17
        assert result.suri_http_cnt == 210
        assert result.info.machine.name == "windows-machine-1"
        assert isinstance(result.info.machine.started_on, datetime.datetime)
        assert str(result.info.machine.started_on) == "2024-03-29 14:00:26"
        assert result.vt_file_summary == "66/76"
        assert result.vt_url_summary == "20/30"
        assert result.clamav == []

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_cape_configs(self):
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.cape_configs(TEST_TASK_ID)
        assert isinstance(actual, list)
        assert all([isinstance(cfg, schema.AnalysisConfig) for cfg in actual])
        assert len(actual) == 1

    def test_calls_no_data(self):
        """Test calls returns an empty list if there is no data."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.calls(TEST_TASK_ID)
        assert isinstance(actual, list)
        assert len(actual) == 0

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test__calls(self):
        """Test calls returns a list of calls."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo._calls(TEST_TASK_ID) # type: ignore
        assert isinstance(actual, list)
        assert len(actual) == sum(TEST_PIDS)
        assert all([isinstance(call, schema.Call) for call in actual])

    @pytest.mark.parametrize("pid, expected_count", [(None, sum(TEST_PIDS)), (1, 1), (5, 5), (6, 0), ((1, 2, 3), 6)])
    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test__calls(self, pid: int, expected_count):
        """Test calls returns a list of calls filtered by process ID."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo._calls(TEST_TASK_ID, pid) # type: ignore
        assert isinstance(actual, list)
        assert len(actual) == expected_count
        assert all([isinstance(call, schema.Call) for call in actual])


    def test_calls(self, monkeypatch):
        """Test `calls` calls `_calls`."""
        mongo = mongodb.MongoDBReports(self.cfg)

        call_count = 0
        def _calls(task_id, pid=None):
            nonlocal call_count
            call_count += 1
            assert isinstance(task_id, int)
            assert pid is None

        with monkeypatch.context() as m:
            m.setattr(mongo, "_calls", _calls)
            mongo.calls(TEST_TASK_ID)
            assert call_count == 1

    def test_calls_by_pid(self, monkeypatch):
        """Test `calls_by_pid` calls `_calls`."""
        mongo = mongodb.MongoDBReports(self.cfg)

        call_count = 0
        def _calls(task_id, pid=None):
            nonlocal call_count
            call_count += 1
            assert isinstance(task_id, int)
            assert isinstance(pid, int)

        with monkeypatch.context() as m:
            m.setattr(mongo, "_calls", _calls)
            mongo.calls_by_pid(TEST_TASK_ID, 1)
            assert call_count == 1

