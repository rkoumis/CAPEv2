from importlib import import_module
from types import SimpleNamespace


timeout_manager_module = import_module("guac.timeout_manager")


class TestSessionTimeoutManager:
    def test_idle_timeout_defaults_to_zero_when_not_configured(self, monkeypatch):
        monkeypatch.setattr(timeout_manager_module, "web_cfg", SimpleNamespace())

        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.20", "tester")

        assert manager.idle_timeout_ms == 0
        assert manager.activity_check_interval is None
        manager.last_activity = 0
        assert manager.is_timed_out() is False

    def test_idle_timeout_zero_disables_timeout_checks(self, monkeypatch):
        monkeypatch.setattr(
            timeout_manager_module,
            "web_cfg",
            SimpleNamespace(guacamole=SimpleNamespace(idle_timeout_ms=0, activity_check_interval=1)),
        )

        manager = timeout_manager_module.SessionTimeoutManager("192.168.56.21", "tester")

        assert manager.idle_timeout_ms == 0
        assert manager.activity_check_interval is None
        manager.last_activity = 0
        assert manager.is_timed_out() is False
