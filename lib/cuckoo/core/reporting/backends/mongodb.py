import itertools
import logging
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any, Generator, Mapping, TypeAlias, cast

import pymongo
import pymongo.collection
import pymongo.database
import pymongo.errors
import pymongo.results
from bson.objectid import ObjectId

from lib.cuckoo.common import config
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.reporting import api, schema

from ..types import SearchCategories

log = logging.getLogger(__name__)


# TODO retry logic - graceful_auto_reconnect
# TODO mongo hooks for files - normalize / denormalize / remove task references / delete unused file docs

MongoDoc: TypeAlias = Mapping[str, Any]

ANALYSIS_COLLECTION = "analysis"
CALLS_COLLECTION = "calls"
CUCKOO_COLLECTION = "cuckoo_schema"
FILES_COLLECTION = "files"

_ID_FIELD = "_id"
INFO_FIELD = "info"
INFO_ID_FIELD = f"{INFO_FIELD}.id"
# _task_ids = "_task_ids"
# file_key = "sha256"
# info = "info"
# info_id = "info.id"
# target = "target"
# version = "version"


class MongoDBReports(api.Reports):
    def __init__(self, cfg: config.Config):
        if not hasattr(cfg, "mongodb"):
            raise CuckooOperationalError("mongodb must be configured")

        mongo_cfg = cast(dict[str, str], cfg.mongodb)
        db_name = mongo_cfg.get("db", "cuckoo")
        _init_pymongo_logging(mongo_cfg)
        self._client = _pymongo_client(mongo_cfg)
        self._database: pymongo.database.Database[MongoDoc] = self._client[db_name]
        self._analysis_collection = self._database[ANALYSIS_COLLECTION]
        self._calls_collection = self._database[CALLS_COLLECTION]
        self._cuckoo_collection = self._database[CUCKOO_COLLECTION]
        self._files_collection = self._database[FILES_COLLECTION]

    def ping(self) -> bool:
        try:
            self._client.admin.command("ping")
        except pymongo.errors.ConnectionFailure:
            return False
        return True

    def get(self, task_id: int) -> dict:
        query = {INFO_ID_FIELD: task_id}
        report = self._analysis_collection.find_one(filter=query)
        return report if isinstance(report, dict) else {}

    def behavior(self, task_id: int) -> schema.Behavior | None:
        query = {INFO_ID_FIELD: task_id}
        projection = {
            _ID_FIELD: 0,
            "behavior.processes": 1,
            "behavior.processtree": 1,
            "detections2pid": 1,
        }
        if result := self._analysis_collection.find_one(filter=query, projection=projection):
            detections2pid = result.get("detections2pid")
            behavior = result.get("behavior", {})
            processes = behavior.get("processes", [])
            for process in processes:
                if pid := process.get("process_id"):
                    process["calls"] = self._calls(task_id, pid)
                else:
                    process["calls"] = []
            process_tree = behavior.get("processtree")
            return schema.Behavior(processes=processes, process_tree=process_tree, detections2pid=detections2pid)

    def delete(self, task_id: int) -> bool:
        query = {INFO_ID_FIELD: task_id}
        rslt: pymongo.results.DeleteResult = self._analysis_collection.delete_one(filter=query)
        return True if rslt.deleted_count > 0 else False

    def _find_info(self, filter: dict[str, Any], limit: int = 0) -> list[schema.Info]:
        """Search for tasks using the specified filter."""
        results = self._analysis_collection.find(filter=filter, projection={_ID_FIELD: 0, INFO_FIELD: 1}, limit=limit)
        retval: list[schema.Info] = []
        for result in results:
            if info := result.get(INFO_FIELD):
                retval.append(schema.Info(**info))
        return retval

    def search(self, term, value, limit: int = 0, projection=None) -> list[schema.Info]:
        pass

    def search_by_category(self, category: SearchCategories, limit: int = 0) -> list[schema.Info]:
        filter = {"info.category": category.value}
        return self._find_info(filter=filter, limit=limit)

    def search_by_user(self, term, value, user_id=False, privs=False, limit: int = 0) -> list[schema.Info]:
        pass

    def search_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        filter = {"target.file.file_ref": sha256}
        return self._find_info(filter=filter, limit=limit)

    # TODO: @josh-feather add unit-tests
    def search_payloads_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        filter = {"CAPE.payloads.file_ref": sha256}
        return self._find_info(filter=filter, limit=limit)

    # TODO: @josh-feather add unit-tests
    def search_dropped_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        filter = {"dropped.file_ref": sha256}
        return self._find_info(filter=filter, limit=limit)

    # TODO: @josh-feather add unit-tests
    def search_procdump_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        filter = {"dropped.file_ref": sha256}
        return self._find_info(filter=filter, limit=limit)

    # TODO: @josh-feather find example report with data.
    def search_suricata_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        filter = {"suricata.files.file_info.sha256": sha256}
        return self._find_info(filter=filter, limit=limit)

    # TODO: @josh-feather add unit-tests
    def search_detections_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        filter = {"$or": [{"detections.details.VirusTotal": sha256}, {"detections.details.Yara": sha256}]}
        return self._find_info(filter=filter, limit=limit)

    # TODO: @josh-feather add unit-tests
    def cape(self, task_id: int) -> schema.CAPE | None:
        configs = self.cape_configs(task_id)
        payloads = self.cape_payloads(task_id)
        if configs and payloads:
            return schema.CAPE(payloads=payloads, configs=configs)

    def cape_configs(self, task_id: int) -> list[schema.AnalysisConfig] | None:
        if result := self._analysis_collection.find_one(
            filter={INFO_ID_FIELD: task_id},
            projection={
                "CAPE.configs": 1,
            },
        ):
            configs = result.get("CAPE", {}).get("configs", [])
            return [schema.AnalysisConfig(**cfg) for cfg in configs]

    # TODO: @josh-feather add unit-tests
    def cape_payloads(self, task_id: int) -> list[schema.CAPE.Payload] | None:
        if result := self._analysis_collection.find_one(
            filter={INFO_ID_FIELD: task_id},
            projection={
                "CAPE.payloads": 1,
            },
        ):
            payloads = result.get("CAPE", {}).get("payloads", [])
            return [schema.CAPE.Payload(**payload) for payload in payloads]

    # TODO: @josh-feather implement this
    def iocs(self, task_id: int) -> schema.IOC | None:
        return self.get(task_id)

    def summary(self, task_id: int) -> schema.Summary | None:
        query = {INFO_ID_FIELD: task_id}
        projection = {
            _ID_FIELD: 0,
            INFO_FIELD: 1,
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
        if report := self._analysis_collection.find_one(filter=query, projection=projection):
            # Rearrange some data for populating the Summary object
            report["vt_file_summary"] = report.get("target", {}).get("file", {}).get("virustotal", {}).get("summary")
            report["vt_url_summary"] = report.get("url", {}).get("virustotal", {}).get("summary")
            report["pcap_sha256"] = report.get("network", {}).get("pcap_sha256")
            report["clamav"] = report.get("target", {}).get("file", {}).get("clamav")
            return schema.Summary(**report)
        return None

    def summaries(self) -> Generator[schema.Summary, None, None]:
        tasks = self._analysis_collection.find({}, {_ID_FIELD: 0, INFO_ID_FIELD: 1})
        for task in tasks:
            task_id = task.get(INFO_FIELD, {}).get("id")
            if task_id is None:
                continue
            if summary := self.summary(task_id):
                yield summary
            else:
                continue

    def recent_suricata_alerts(self, minutes=60) -> list:
        gen_time = datetime.now() - timedelta(minutes=minutes)
        dummy_id = ObjectId.from_datetime(gen_time)
        result = list(
            self._analysis_collection.find(
                filter={"suricata.alerts": {"$exists": True}, _ID_FIELD: {"$gte": dummy_id}},
                projection={"suricata.alerts": 1, INFO_ID_FIELD: 1},
            )
        )
        return result

    def detections(self, task_id: int) -> dict:
        pass

    def dropped(self, task_id: int) -> dict:
        query = {INFO_ID_FIELD: task_id}
        projection = {
            _ID_FIELD: 0,
            "dropped": 1,
            INFO_FIELD: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def memory(self, task_id: int) -> dict:
        query = {INFO_ID_FIELD: task_id}
        projection = {
            _ID_FIELD: 0,
            "memory": 1,
            INFO_FIELD: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def network(self, task_id: int) -> schema.Network | None:
        query = {INFO_ID_FIELD: task_id}
        projection = {
            _ID_FIELD: 0,
            "network": 1,
        }
        if result := self._analysis_collection.find_one(filter=query, projection=projection):
            network = result.get("network")
            return schema.Network(**network) if isinstance(network, dict) else None

    def procdump(self, task_id: int) -> dict:
        query = {INFO_ID_FIELD: task_id}
        projection = {
            _ID_FIELD: 0,
            "procdump": 1,
            INFO_FIELD: 1,
        }
        report = self._analysis_collection.find_one(filter=query, projection=projection)
        return None if not report else report

    def procmemory(self, task_id: int) -> schema.ProcMemory | None:
        query = {INFO_ID_FIELD: task_id}
        projection = {
            _ID_FIELD: 0,
            "procmemory": 1,
        }
        if result := self._analysis_collection.find_one(filter=query, projection=projection):
            procmemory = result.get("procmemory")
            return schema.ProcMemory(**procmemory) if isinstance(procmemory, dict) else None

    def _calls(self, task_id: int, pid: int | Iterable[int] | None = None) -> list[schema.Call]:
        result = self._analysis_collection.find_one(
            filter={INFO_ID_FIELD: task_id},
            projection={
                _ID_FIELD: 0,
                "behavior.processes.process_id": 1,
                "behavior.processes.calls": 1,
            },
        )

        retval: list[schema.Call] = []
        if not result:
            return retval

        pid = [pid] if isinstance(pid, int) else pid

        processes = result.get("behavior", {}).get("processes", [])
        calls = [proc.get("calls", []) for proc in processes if pid is None or proc.get("process_id") in pid]
        call_ids = list(itertools.chain.from_iterable(calls))

        calls_filter: dict[str, Any] = {_ID_FIELD: {"$in": call_ids}}
        if isinstance(pid, Iterable):
            calls_filter = {"$and": [calls_filter, {"pid": {"$in": list(pid)}}]}

        call_docs = self._calls_collection.find(filter=calls_filter, sort=[(_ID_FIELD, 1)])

        for doc in call_docs:
            retval.extend([schema.Call(**call) for call in doc.get("calls", [])])

        return retval

    def calls(self, task_id: int) -> list[schema.Call]:
        return self._calls(task_id)

    def calls_by_pid(self, task_id: int, pid: int) -> list[schema.Call]:
        return self._calls(task_id, pid)

    def suricata(self, task_id) -> schema.Suricata | None:
        filter = {INFO_ID_FIELD: task_id}
        projection = {_ID_FIELD: 0, "suricata": 1}
        if result := self._analysis_collection.find_one(filter=filter, projection=projection):
            suricata = result.get("suricata")
            return schema.Suricata(**suricata) if isinstance(suricata, dict) else None


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
