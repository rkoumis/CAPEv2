import functools
import inspect

import pytest

from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common import config
from lib.cuckoo.core.reporting import api
from lib.cuckoo.core.reporting.backends import null

getfunctions = functools.partial(inspect.getmembers, predicate=inspect.isfunction)


class TestNullReportingBackend:
    def test_has_api_methods(self):
        api_functions = {x for x in getfunctions(api.Reports)}
        assert len(api_functions) > 0
        backend = null.NullReports(config.Config())
        for fn in api_functions:
            with pytest.raises(CuckooOperationalError):
                assert hasattr(backend, fn[0])
                null_fn = getattr(backend, fn[0])
                null_fn()
