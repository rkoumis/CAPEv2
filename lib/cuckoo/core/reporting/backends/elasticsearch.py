from lib.cuckoo.common import config
from lib.cuckoo.core.reporting import api, schema


class ElasticsearchReports(api.Reports):
    def __init__(self, cfg: config.Config):
        pass

    def get(self, task_id: int) -> dict:
        pass

    def delete(self, task_id: int) -> bool:
        pass

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
        pass

    def summary(self, task_id: int) -> schema.Summary:
        pass

    def recent_suricata_alerts(self, minutes=60) -> list:
        pass
