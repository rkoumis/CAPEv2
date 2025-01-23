import enum

from lib.cuckoo.common import config
from .api import Reports
from .backends import mongodb, elasticsearch, null


class Backend(enum.Enum):
    MONGODB = enum.auto()
    ELASTICSEARCH = enum.auto
    NONE = enum.auto()


# Reports are disabled by default. Enable it by configuring MongoDB or Elasticsearch
# and calling init_reports.
_enabled: bool = False
_backend: Backend = Backend.NONE


def enabled():
    return _enabled


def disabled():
    return not enabled()


def configured(cfg: config.Config) -> bool:
    if cfg.mongodb.enabled:
        return True
    if cfg.elasticsearchdb.enabled:
        return True
    return False


def init_reports(cfg: config.Config) -> Reports:
    global _enabled, _backend
    if cfg.mongodb.enabled:
        _enabled, _backend = True, Backend.MONGODB
        return mongodb.MongoDBReports(cfg)
    elif cfg.elasticsearchdb.enabled:
        _enabled, _backend = True, Backend.ELASTICSEARCH
        return elasticsearch.ElasticsearchReports(cfg)
    _enabled, _backend = False, null.Null(cfg)
