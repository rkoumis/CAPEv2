import pytest

from lib.cuckoo.core.reporting import api
from lib.cuckoo.core.reporting.backends import elasticsearch

from .conftest import getfunctions


@pytest.mark.usefixtures("elasticsearch_config")
class TestElasticsearchReportingBackend:
    def test_has_api_methods(self):
        api_functions = {x for x in getfunctions(api.Reports)}
        assert len(api_functions) > 0
        backend = elasticsearch.ElasticsearchReports
        for fn in api_functions:
            assert hasattr(backend, fn[0])
            msg = f"reporting backend {backend} does not implement '{fn[0]}'"
            assert getattr(backend, fn[0]) != fn[1], msg

    @pytest.mark.skip("requires full ElasticSearchReport implementation")
    def test_ping(self):
        es = elasticsearch.ElasticsearchReports(self.cfg)
        result = es.ping()
        assert result is True

    @pytest.mark.skip("requires full ElasticSearchReport implementation")
    def test_ping_fails(self):
        es = elasticsearch.ElasticsearchReports(self.cfg)
        result = es.ping()
        assert result is False
