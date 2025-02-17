from lib.cuckoo.common import config
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.reporting import api


class NullReports(api.Reports):
    def __init__(self, _: config.Config):
        pass

    def __getattribute__(self, name):
        def fn(*args, **kwargs):
            raise CuckooOperationalError("reporting backend does not support '%s'" % name)

        return fn
