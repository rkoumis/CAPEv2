from typing import Optional

from lib.cuckoo.core.reporting import schema


class Reports:
    """Interface to report backends."""

    def get(self, task_id: int) -> dict:
        raise NotImplementedError()

    def behavior(self, task_id: int) -> schema.Behavior:
        raise NotImplementedError()

    def delete(self, task_id: int) -> bool:
        raise NotImplementedError()

    def search(self, term, value, limit=False, projection=None) -> list:
        raise NotImplementedError()

    def search_by_user(self, term, value, user_id=False, privs=False) -> list:
        raise NotImplementedError()

    def search_by_sha256(self, sha256: str, limit=False) -> list:
        raise NotImplementedError()

    def cape_configs(self, task_id: int) -> Optional[schema.AnalysisConfigs]:
        raise NotImplementedError()

    def detections_by_sha256(self, sha256: str) -> dict:
        raise NotImplementedError()

    def iocs(self, task_id: int) -> dict:
        raise NotImplementedError()

    def summary(self, task_id: int) -> Optional[schema.Summary]:
        raise NotImplementedError()

    def recent_suricata_alerts(self, minutes=60) -> list:
        raise NotImplementedError()

    def dropped(self, task_id: int) -> dict:
        raise NotImplementedError()

    def memory(self, task_id: int) -> dict:
        raise NotImplementedError()

    def network(self, task_id: int) -> dict:
        raise NotImplementedError()

    def procdump(self, task_id: int) -> dict:
        raise NotImplementedError()

    def procmemory(self, task_id: int) -> dict:
        raise NotImplementedError()
