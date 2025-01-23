from lib.cuckoo.common import config
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.reporting import api


class Null(api.Reports):
    def __init__(self, cfg: config.Config):
        pass

    def __getattr__(self, name):
        raise CuckooOperationalError("reporting backend does not support '%s'" % name)
