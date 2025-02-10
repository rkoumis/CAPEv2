from typing import Generator

from lib.cuckoo.core.reporting import schema

from .types import SearchCategories


class Reports:
    """Interface to report backends."""

    def get(self, task_id: int) -> dict:
        raise NotImplementedError()

    def behavior(self, task_id: int) -> schema.Behavior | None:
        raise NotImplementedError()

    def delete(self, task_id: int) -> bool:
        raise NotImplementedError()

    def search(self, term, value, limit: int = 0, projection=None) -> list[schema.Info]:
        raise NotImplementedError()

    def search_by_category(self, category: SearchCategories, limit: int = 0) -> list[schema.Info]:
        raise NotImplementedError()

    def search_by_user(self, term, value, user_id=False, privs=False) -> list[schema.Info]:
        raise NotImplementedError()

    def search_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        raise NotImplementedError()

    def search_payloads_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        raise NotImplementedError()

    def search_dropped_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        raise NotImplementedError()

    def search_procdump_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        raise NotImplementedError()

    def search_suricata_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        raise NotImplementedError()

    def search_detections_by_sha256(self, sha256: str, limit: int = 0) -> list[schema.Info]:
        raise NotImplementedError()

    def cape(self, task_id: int) -> list[schema.CAPE]:
        raise NotImplementedError()

    def cape_configs(self, task_id: int) -> list[schema.AnalysisConfig] | None:
        raise NotImplementedError()

    def cape_payloads(self, task_id: int) -> ???:
        raise NotImplementedError()

    def iocs(self, task_id: int): # -> schema.IOC | None:
        raise NotImplementedError()

    def summary(self, task_id: int) -> schema.Summary | None:
        raise NotImplementedError()

    def summaries(self) -> Generator[schema.Summary, None, None]:
        raise NotImplementedError()

    def recent_suricata_alerts(self, minutes=60) -> list[schema.Suricata]:
        raise NotImplementedError()

    def detections(self, task_id: int) -> dict:
        raise NotImplementedError()

    def dropped(self, task_id: int) -> dict:
        raise NotImplementedError()

    def memory(self, task_id: int) -> dict:
        raise NotImplementedError()

    def network(self, task_id: int) -> schema.Network | None:
        raise NotImplementedError()

    def payloads(self, task_id: int) -> dict:
        raise NotImplementedError()

    def procdump(self, task_id: int) -> dict:
        raise NotImplementedError()

    def procmemory(self, task_id: int) -> schema.ProcMemory | None:
        raise NotImplementedError()

    def calls(self, task_id: int) -> list[schema.Call]:
        raise NotImplementedError()

    def calls_by_pid(self, task_id: int, pid: int) -> list[schema.Call]:
        raise NotImplementedError()

    def suricata(self, task_id) -> schema.Suricata | None:
        raise NotImplementedError()
