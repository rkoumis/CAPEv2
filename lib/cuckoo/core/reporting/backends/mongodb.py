import itertools
import logging
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional, cast, TypeAlias
from collections.abc import Iterable

import pymongo
import pymongo.collection
import pymongo.database
import pymongo.results
from bson.objectid import ObjectId

from lib.cuckoo.common import config
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.reporting import api, schema

log = logging.getLogger(__name__)


# TODO retry logic - graceful_auto_reconnect
# TODO mongo hooks for files - normalize / denormalize / remove task references / delete unused file docs

MongoDoc: TypeAlias = Mapping[str, Any]


class MongoDBReports(api.Reports):
    def __init__(self, cfg: config.Config):
        if not hasattr(cfg, "mongodb"):
            raise CuckooOperationalError("mongodb must be configured")

        mongo_cfg = cast(dict[str, str], cfg.mongodb)
        db_name = mongo_cfg.get("db", "cuckoo")
        _init_pymongo_logging(mongo_cfg)
        self._client = _pymongo_client(mongo_cfg)
        self._database: pymongo.database.Database[MongoDoc] = self._client[db_name]
        self._analysis_collection = self._database[_analysis_coll]
        self._calls_collection = self._database[_calls_coll]

    def get(self, task_id: int) -> dict:
        query = {_info_id: task_id}
        report = self._analysis_collection.find_one(filter=query)
        return {} if not report else report

    def behavior(self, task_id: int) -> schema.Behavior:
        query = {_info_id: task_id}
        projection = {
            _id: 0,
            "behavior.processes": 1,
            "behavior.processtree": 1,
            "detections2pid": 1,
            _info: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def delete(self, task_id: int) -> bool:
        query = {_info_id: task_id}
        rslt: pymongo.results.DeleteResult = self._analysis_collection.delete_one(filter=query)
        return True if rslt.deleted_count > 0 else False

    def search(self, term, value, limit: int = 0, projection=None) -> list:
        pass

    def search_by_user(self, term, value, user_id=False, privs=False) -> list:
        pass

    def search_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        results = self._analysis_collection.find(
            filter={"target.file.file_ref": sha256}, projection={"_id": 0, "info": 1}, limit=limit
        )
        retval: list[schema.Info] = []
        for result in results:
            info = result.get("info", {})
            retval.append(schema.Info(**info))
        return retval

    def search_payloads_by_sha256(self, sha256: str) -> list:
        pass

    def search_dropped_by_sha256(self, sha256: str) -> list:
        pass

    def search_procdump_by_sha256(self, sha256: str) -> list:
        pass

    def search_suricata_by_sha256(self, sha256: str) -> list[schema.Suricata]:
        pass

    def cape_configs(self, task_id: int) -> list[schema.AnalysisConfig]:
        result = self._analysis_collection.find_one(
            filter={_info_id: task_id},
            projection={
                "CAPE.configs": 1,
            },
        )
        retval: list[schema.AnalysisConfig] = []
        if result:
            configs = result.get("CAPE", {}).get("configs", [])
            retval.extend([schema.AnalysisConfig(**cfg) for cfg in configs])
        return retval

    def detections_by_sha256(self, sha256: str) -> dict:
        pass

    def iocs(self, task_id: int) -> dict:
        # there's no well-defined representation of iocs data yet; defer to full get
        return self.get(task_id)

    def summary(self, task_id: int) -> Optional[schema.Summary]:
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
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        if report:
            # Rearrange some data for populating the Summary object
            report["vt_file_summary"] = report.get("target", {}).get("file", {}).get("virustotal", {}).get("summary")
            report["vt_url_summary"] = report.get("url", {}).get("virustotal", {}).get("summary")
            report["pcap_sha256"] = report.get("network", {}).get("pcap_sha256")
            report["clamav"] = report.get("target", {}).get("file", {}).get("clamav")
            return schema.Summary(**report)
        return None

    def recent_suricata_alerts(self, minutes=60) -> list:
        gen_time = datetime.now() - timedelta(minutes=minutes)
        dummy_id = ObjectId.from_datetime(gen_time)
        result = list(
            self._analysis_collection.find(
                filter={"suricata.alerts": {"$exists": True}, "_id": {"$gte": dummy_id}},
                projection={"suricata.alerts": 1, "info.id": 1},
            )
        )
        return result

    def dropped(self, task_id: int) -> dict:
        query = {_info_id: task_id}
        projection = {
            _id: 0,
            "dropped": 1,
            _info: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def memory(self, task_id: int) -> dict:
        query = {_info_id: task_id}
        projection = {
            _id: 0,
            "memory": 1,
            _info: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def network(self, task_id: int) -> dict:
        query = {_info_id: task_id}
        projection = {
            _id: 0,
            "network": 1,
            "suricata": 1,
            "pcapng": 1,
            _info: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def procdump(self, task_id: int) -> dict:
        query = {_info_id: task_id}
        projection = {
            _id: 0,
            "procdump": 1,
            _info: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def procmemory(self, task_id: int) -> dict:
        query = {_info_id: task_id}
        projection = {
            _id: 0,
            "procmemory": 1,
            _info: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def _calls(self, task_id: int, pid: int | Iterable[int] | None = None) -> list[schema.Call]:
        result = self._analysis_collection.find_one(
            filter={_info_id: task_id},
            projection={
                _id: 0,
                "behavior.processes.calls": 1,
            },
        )

        retval: list[schema.Call] = []
        if not result:
            return retval

        processes = result.get("behavior", {}).get("processes", {})
        calls = [proc.get("calls", {}) for proc in processes]
        call_ids = list(itertools.chain.from_iterable(calls))

        calls_filter: dict[str, Any] = {_id: {"$in": call_ids}}
        if isinstance(pid, int):
            calls_filter = {"$and": [calls_filter, {"pid": pid}]}
        elif isinstance(pid, Iterable):
            calls_filter = {"$and": [calls_filter, {"pid": {"$in": list(pid)}}]}

        call_docs = self._calls_collection.find(filter=calls_filter, sort=[(_id, 1)])

        for doc in call_docs:
            retval.extend([schema.Call(**call) for call in doc.get("calls", [])])

        return retval

    def calls(self, task_id: int) -> list[schema.Call]:
        return self._calls(task_id)

    def calls_by_pid(self, task_id: int, pid: int) -> list[schema.Call]:
        return self._calls(task_id, pid)

    def suricata(self, task_id) -> list[schema.Suricata]:
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


def _pymongo_client(cfg: dict[str, Any]) -> pymongo.MongoClient[Mapping[str, Any]]:
    return pymongo.MongoClient(
        host=cfg.get("host", "127.0.0.1"),
        port=cfg.get("port", 27017),
        username=cfg.get("username"),
        password=cfg.get("password"),
        authSource=cfg.get("authsource", "cuckoo"),
        tlsCAFile=cfg.get("tlscafile", None),
    )


def _init_pymongo_logging(cfg: dict[str, str]) -> None:
    mongodb_log_level = cfg.get("log_level", "ERROR").upper()
    logging.getLogger("pymongo").setLevel(mongodb_log_level)
