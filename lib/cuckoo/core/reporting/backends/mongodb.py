import logging

import pymongo
import pymongo.collection
import pymongo.database
import pymongo.results

from lib.cuckoo.common import config
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.reporting import api, schema

log = logging.getLogger(__name__)


class MongoDBReports(api.Reports):
    def __init__(self, cfg: config.Config):
        if not hasattr(cfg, "mongodb"):
            raise CuckooOperationalError("mongodb must be configured")
        mongodb_cfg: dict = cfg.mongodb

        self._client: pymongo.MongoClient = _pymongo_client(mongodb_cfg)
        dbname = mongodb_cfg.get("db", "cuckoo")
        self._database: pymongo.database.Database = self._client[dbname]
        self._reports: pymongo.collection.Collection = self._database[_analysis_coll]

        _init_pymongo_logging(mongodb_cfg)

    def get(self, task_id: int) -> dict:
        query = {_info_id: task_id}
        report = self._reports.find_one(filter=query)
        return {} if not report else report

    def delete(self, task_id: int) -> bool:
        query = {_info_id: task_id}
        rslt: pymongo.results.DeleteResult = self._reports.delete_one(filter=query)
        return True if rslt.deleted_count > 0 else False

    def search(self, term, value, limit=False, projection=None) -> list:
        pass

    def search_by_user(self, term, value, user_id=False, privs=False) -> list:
        pass

    def search_by_sha256(self, sha256: str, limit=False) -> list:
        pass

    def cape_configs(self, task_id: int) -> dict:
        pass

    def detections_by_sha256(self, sha256: str) -> dict:
        pass

    def iocs(self, task_id: int) -> dict:
        # there's no well-defined representation of iocs data yet; defer to full get
        return self.get(task_id)

    def summary(self, task_id: int) -> schema.Summary:
        query = {_info_id: task_id}
        projection = {
            _id: 0,
            _info: 1,
            "target.file.virustotal.summary": 1,
            "url.virustotal.summary": 1,
            "malscore": 1,
            "detections": 1,
            "network.pcap_sha256": 1,
            "mlist_cnt": 1,
            "f_mlist_cnt": 1,
            "target.file.clamav": 1,
            "suri_tls_cnt": 1,
            "suri_alert_cnt": 1,
            "suri_http_cnt": 1,
            "suri_file_cnt": 1,
            "trid": 1,
        }
        report = self._reports.find_one(filter=query, projection=projection)
        return None if not report else schema.Summary(**report)

    def recent_suricata_alerts(self, minutes=60) -> list:
        pass


# Temporarily duped with mongodb_constants
_analysis_coll = "analysis"
_calls_coll = "calls"
_cuckoo_coll = "cuckoo_schema"
_files_coll = "files"
_file_key = "sha256"
_id = "_id"
_info = "info"
_info_id = "info.id"
_target = "target"
_task_ids_key = "_task_ids"
_version = "version"


def _pymongo_client(cfg: dict) -> pymongo.MongoClient:
    return pymongo.MongoClient(
        host=cfg.get("host", "127.0.0.1"),
        port=cfg.get("port", 27017),
        username=cfg.get("username"),
        password=cfg.get("password"),
        authSource=cfg.get("authsource", "cuckoo"),
        tlsCAFile=cfg.get("tlscafile", None),
    )


def _init_pymongo_logging(cfg: dict) -> None:
    mongodb_log_level = cfg.get("log_level", "ERROR")
    level = logging.getLevelName(mongodb_log_level.upper())
    logging.getLogger("pymongo").setLevel(level)
