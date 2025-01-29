import functools
import inspect

from lib.cuckoo.core.reporting import api
from lib.cuckoo.core.reporting.backends import mongodb

getfunctions = functools.partial(inspect.getmembers, predicate=inspect.isfunction)


class TestMongoDBReportingBackend:
    def test_has_api_methods(self):
        api_functions = {x for x in getfunctions(api.Reports)}
        assert len(api_functions) > 0
        backend = mongodb.MongoDBReports
        for fn in api_functions:
            assert hasattr(backend, fn[0])
            msg = f"reporting backend {backend} does not implement '{fn[0]}'"
            assert getattr(backend, fn[0]) != fn[1], msg
