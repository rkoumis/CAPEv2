import datetime

from lib.cuckoo.core.reporting.types import SearchCategories
import mongomock
import pytest
import pymongo

from lib.cuckoo.core.reporting import api, schema
from lib.cuckoo.core.reporting.backends import mongodb

from .conftest import TEST_PIDS, TEST_TASK_IDS, getfunctions

TEST_TASK_ID = TEST_TASK_IDS[0]


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

    def test_ping(self):
        mongo = mongodb.MongoDBReports(self.cfg)
        result = mongo.ping()
        assert result is True

    def test_ping_fails(self, monkeypatch):
        mongo = mongodb.MongoDBReports(self.cfg)

        def connection_failure(*args, **kwargs):
            raise pymongo.errors.ConnectionFailure()

        with monkeypatch.context() as m:
            m.setattr(mongo._client.admin, "command", connection_failure)
            result = mongo.ping()
        assert result is False

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_behavior(self):
        """Retrieve behavior data."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.behavior(TEST_TASK_ID)
        assert isinstance(actual, schema.Behavior)
        assert len(actual.processes) == len(TEST_PIDS)
        for process in actual.processes:
            assert isinstance(process, schema.Behavior.Process)
            assert len(process.calls) == process.process_id
            assert all([isinstance(call, schema.Call) for call in process.calls])

    def test_behavior_no_data(self):
        """Test `None` is returned when no matching task exists."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.behavior(TEST_TASK_ID)
        assert actual is None

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_search_by_sha256(self):
        """Test searching by sha256."""
        mongo = mongodb.MongoDBReports(self.cfg)
        sha256 = "a" * 64
        actual = mongo.search_by_sha256(sha256)
        assert len(actual) == len(TEST_TASK_IDS)
        assert all([isinstance(hit, schema.Info) for hit in actual])
        assert actual[0].id == TEST_TASK_ID

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_search_by_sha256_with_limit(self):
        """Test searching by sha256."""
        mongo = mongodb.MongoDBReports(self.cfg)
        sha256 = "a" * 64
        limit = 1
        actual = mongo.search_by_sha256(sha256, limit=limit)
        assert len(actual) == limit
        assert all([isinstance(hit, schema.Info) for hit in actual])
        assert actual[0].id == TEST_TASK_ID

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_search_suricata_by_sha256(self):
        """Retrieve suricata object from sha256."""
        mongo = mongodb.MongoDBReports(self.cfg)
        sha256 = "a" * 64
        actual = mongo.search_suricata_by_sha256(sha256)
        assert len(actual) == len(TEST_TASK_IDS)
        assert all([isinstance(hit, schema.Info) for hit in actual])
        assert actual[0].id == TEST_TASK_ID

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_search_suricata_by_sha256_with_limit(self):
        """Retrieve suricata object from sha256."""
        mongo = mongodb.MongoDBReports(self.cfg)
        sha256 = "a" * 64
        limit = 1
        actual = mongo.search_suricata_by_sha256(sha256, limit=limit)
        assert len(actual) == limit
        assert all([isinstance(hit, schema.Info) for hit in actual])
        assert actual[0].id == TEST_TASK_ID

    def test_search_suricata_by_sha256_no_results(self):
        """Retrieve suricata object from sha256."""
        mongo = mongodb.MongoDBReports(self.cfg)
        sha256 = "z" * 64
        actual = mongo.search_suricata_by_sha256(sha256)
        assert len(actual) == 0

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_search_by_category(self):
        """Find tasks of a certain category."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.search_by_category(SearchCategories.FILE)
        assert len(actual) == len(TEST_TASK_IDS)
        assert all([isinstance(hit, schema.Info) for hit in actual])

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_search_by_category_with_limit(self):
        """Find tasks of a certain category."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.search_by_category(SearchCategories.FILE, limit=1)
        assert len(actual) == 1

    def test_search_by_category_no_data(self):
        """Ensure empty list is returned if there is no matching data."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.search_by_category(SearchCategories.FILE)
        assert len(actual) == 0

    def test_nonexistent_summary(self):
        """Ask for a summary that is not present in the MongoDB."""
        mongo = mongodb.MongoDBReports(self.cfg)
        result = mongo.summary(TEST_TASK_ID)
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
    def test_summaries(self):
        """Retrieve Summaries from MongoDB."""
        mongo = mongodb.MongoDBReports(self.cfg)
        results = mongo.summaries()
        result_count = 0
        for result in results:
            result_count += 1
            assert isinstance(result, schema.Summary)
        assert result_count == len(TEST_TASK_IDS)

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_network(self):
        """Retrieve network data from MongoDB"""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.network(TEST_TASK_ID)
        assert isinstance(actual, schema.Network)
        assert actual.pcap_sha256 == "PCAP" * 16

    def test_network_no_data(self):
        """Retrieve network data from MongoDB"""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.network(TEST_TASK_ID)
        assert actual is None

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_cape_configs(self):
        """Retrieve analysis configs from MongoDB."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.cape_configs(TEST_TASK_ID)
        assert isinstance(actual, list)
        assert all([isinstance(cfg, schema.AnalysisConfig) for cfg in actual])
        assert len(actual) == 1

    def test_cape_configs_no_data(self):
        """Retrieve analysis configs from MongoDB."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.cape_configs(TEST_TASK_ID)
        assert actual is None

    @pytest.mark.parametrize("pid, expected_count", [(None, sum(TEST_PIDS)), (1, 1), (5, 5), (6, 0), ((1, 2, 3), 6)])
    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test__calls(self, pid: int, expected_count):
        """Test calls returns a list of calls filtered by process ID."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo._calls(TEST_TASK_ID, pid)  # type: ignore
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

    def test_calls_no_data(self):
        """Test calls returns an empty list if there is no data."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.calls(TEST_TASK_ID)
        assert isinstance(actual, list)
        assert len(actual) == 0

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

    @pytest.mark.usefixtures("mongodb_populate_test_data")
    def test_suricata(self):
        """Retrieve suricata object from sha256."""
        mongo = mongodb.MongoDBReports(self.cfg)
        actual = mongo.suricata(TEST_TASK_ID)
        assert isinstance(actual, schema.Suricata)
        assert "example.com" in actual.http
