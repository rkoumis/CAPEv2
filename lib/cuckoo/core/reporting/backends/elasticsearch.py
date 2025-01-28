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

    def search(self, term, value, limit=False, projection=None) -> list:
        pass

    def search_by_user(self, term, value, user_id=False, privs=False) -> list:
        pass

    def search_by_sha256(self, sha256: str, limit=False) -> list:
        pass

    def cape_configs(self, task_id: int) -> schema.AnalysisConfigs:
        tmp = self.es.search(index=get_analysis_index(), query=get_query_by_info_id(str(task_id)))["hits"]["hits"]
        if len(tmp) >= 1:
            buf = tmp[-1]["_source"]
            return schema.AnalysisConfigs(**buf)
        return None

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
