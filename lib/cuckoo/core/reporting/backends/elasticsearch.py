from typing import Optional

from lib.cuckoo.common import config
from lib.cuckoo.core.reporting import api, schema

try:
    # TODO implement these right here
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index, get_query_by_info_id
except ImportError:
    pass


class ElasticsearchReports(api.Reports):
    def __init__(self, cfg: config.Config):
        self.es = elastic_handler

    def ping(self):
        return self.es.ping()

    def get(self, task_id: int) -> dict:
        tmp = self.es.search(index=get_analysis_index(), query=get_query_by_info_id(str(task_id)))["hits"]["hits"]
        if tmp:
            buf = tmp[-1]["_source"]
            return buf
        else:
            return {}

    def behavior(self, task_id: int) -> dict:
        pass

    def delete(self, task_id: int) -> bool:
        pass

    def search(self, term, value, limit: int = 0, projection=None) -> list:
        pass

    def search_by_user(self, term, value, user_id=False, privs=False) -> list:
        pass

    def search_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        pass

    def search_payloads_by_sha256(self, sha256: str, limit: int = 0) -> list:
        pass

    def search_dropped_by_sha256(self, sha256: str, limit: int = 0) -> list:
        pass

    def search_procdump_by_sha256(self, sha256: str, limit: int = 0) -> list:
        pass

    def search_suricata_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Suricata]:
        pass

    def cape_configs(self, task_id: int) -> list[schema.AnalysisConfig]:
        resp = self.es.search(index=get_analysis_index(), query=get_query_by_info_id(str(task_id)))
        retval = []
        for hit in resp["hits"]["hits"]:
            retval.append(schema.AnalysisConfig(**hit["_source"]))
        return retval

    def detections_by_sha256(self, sha256: str) -> dict:
        pass

    def iocs(self, task_id: int) -> dict:
        pass

    def summary(self, task_id: int) -> Optional[schema.Summary]:
        rtmp = self.es.search(
            index=get_analysis_index(),
            query=get_query_by_info_id(str(task_id)),
            _source=[
                "info",
                "target.file.virustotal.summary",
                "url.virustotal.summary",
                "malscore",
                "detections",
                "network.pcap_sha256",
                "mlist_cnt",
                "f_mlist_cnt",
                "target.file.clamav",
                "suri_tls_cnt",
                "suri_alert_cnt",
                "suri_http_cnt",
                "suri_file_cnt",
                "trid",
            ],
        )["hits"]["hits"]
        if len(rtmp) >= 1:
            rtmp = rtmp[-1]["_source"]
            return schema.Summary(**rtmp)
        else:
            return None

    def recent_suricata_alerts(self, minutes=60) -> list:
        pass

    def dropped(self, task_id: int) -> dict:
        pass

    def memory(self, task_id: int) -> dict:
        pass

    def network(self, task_id: int) -> dict:
        pass

    def procdump(self, task_id: int) -> dict:
        pass

    def procmemory(self, task_id: int) -> dict:
        pass

    def calls(self, task_id: int) -> list[schema.Call]:
        pass

    def calls_by_pid(self, task_id: int, pid: int) -> list[schema.Call]:
        pass

    def suricata(self, task_id) -> schema.Suricata | None:
        pass
