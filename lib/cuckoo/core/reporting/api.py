class Reports:
    """Interface to report backends."""

    def get(self, task_id: int) -> dict:
        raise NotImplementedError()

    def delete(self, task_id: int) -> bool:
        raise NotImplementedError()

    def search(self, term, value, limit=False, projection=None) -> list:
        raise NotImplementedError()

    def search_by_user(self, term, value, user_id=False, privs=False) -> list:
        raise NotImplementedError()

    def search_by_sha256(self, sha256: str, limit=False) -> list:
        raise NotImplementedError()

    def cape_configs(self, task_id: int) -> dict:
        raise NotImplementedError()

    def detections_by_sha256(self, sha256: str) -> dict:
        raise NotImplementedError()

    def iocs(self, task_id: int) -> dict:
        raise NotImplementedError()

    def summary(self, task_id: int) -> dict:
        raise NotImplementedError()

    def recent_suricata_alerts(self, minutes=60) -> list:
        raise NotImplementedError()
