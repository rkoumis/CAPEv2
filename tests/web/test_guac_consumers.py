import asyncio
import logging
from importlib import import_module
from types import SimpleNamespace

import pytest
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator

consumers = import_module("guac.consumers")
guac_routing = import_module("guac.routing")


class FakeGuacamoleClient:
    instances = []

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connected = False
        self.handshake_kwargs = None
        self.sent_messages = []
        self.closed = False
        self.__class__.instances.append(self)

    def handshake(self, **kwargs):
        self.handshake_kwargs = kwargs
        self.connected = True

    def send(self, message):
        self.sent_messages.append(message)

    def close(self):
        self.closed = True


class FakeTimeoutManager:
    instances = []

    def __init__(self, vm_ip, user, session_id="unknown"):
        self.vm_ip = vm_ip
        self.user = user
        self.session_id = session_id
        self.activity_updates = 0
        self.activity_check_interval = 60
        self.idle_timeout_ms = 120000
        self.is_active = True
        self.__class__.instances.append(self)

    def update_activity(self):
        self.activity_updates += 1

    def set_inactive(self):
        self.is_active = False

    def is_timed_out(self):
        return False

    def get_idle_time_ms(self):
        return 0

    async def complete_analysis(self):
        return True


class ExpiringFakeTimeoutManager(FakeTimeoutManager):
    instances = []

    def __init__(self, vm_ip, user, session_id="unknown"):
        super().__init__(vm_ip, user, session_id=session_id)
        self.activity_check_interval = 0.01
        self.idle_timeout_ms = 120000
        self.complete_analysis_calls = 0

    def is_timed_out(self):
        return True

    def get_idle_time_ms(self):
        return self.idle_timeout_ms + 1

    async def complete_analysis(self):
        self.complete_analysis_calls += 1
        return True


async def _background_task_stub(self):
    await asyncio.Event().wait()


async def _cancel_then_close_read_guacd(self):
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        await self._close_websocket()


@pytest.fixture
def guac_consumer_app_factory(monkeypatch):
    def _build(*, timeout_manager_cls=FakeTimeoutManager, stub_monitor_timeout=True, read_guacd_impl=_background_task_stub):
        FakeGuacamoleClient.instances.clear()
        FakeTimeoutManager.instances.clear()
        ExpiringFakeTimeoutManager.instances.clear()

        monkeypatch.setattr(consumers, "GuacamoleClient", FakeGuacamoleClient)
        monkeypatch.setattr(consumers, "SessionTimeoutManager", timeout_manager_cls)
        monkeypatch.setattr(consumers.GuacamoleWebSocketConsumer, "read_guacd", read_guacd_impl)
        if stub_monitor_timeout:
            monkeypatch.setattr(consumers.GuacamoleWebSocketConsumer, "monitor_timeout", _background_task_stub)
        monkeypatch.setattr(
            consumers,
            "web_cfg",
            SimpleNamespace(
                guacamole=SimpleNamespace(
                    guacd_host="localhost",
                    guacd_port=4822,
                    guacd_recording_path="/tmp/guacrecordings",
                    guest_protocol="vnc",
                    guest_width=1280,
                    guest_height=1024,
                    username="",
                    password="",
                    vnc_host="localhost",
                    vnc_color_depth=16,
                    vnc_cursor="local",
                )
            ),
        )

        return URLRouter(guac_routing.websocket_urlpatterns)

    return _build


@pytest.mark.asyncio
class TestGuacConsumers:
    """Integration-style tests for the Guacamole websocket consumer."""

    async def test_consumer_updates_idle_activity_for_real_guacamole_input(self, guac_consumer_app_factory):
        guac_consumer_app = guac_consumer_app_factory()
        communicator = WebsocketCommunicator(
            guac_consumer_app,
            "/guac/websocket-tunnel/session123/?guest_ip=192.168.56.10&vncport=5901&user=tester&recording_name=task-123",
            subprotocols=["guacamole"],
        )
        timeout_manager = None
        client = None

        try:
            connected, subprotocol = await communicator.connect()
            assert connected is True
            assert subprotocol == "guacamole"

            assert len(FakeGuacamoleClient.instances) == 1
            client = FakeGuacamoleClient.instances[0]
            assert client.handshake_kwargs["hostname"] == "localhost"
            assert client.handshake_kwargs["port"] == 5901
            assert client.handshake_kwargs["recording_name"] == "task-123"

            assert len(FakeTimeoutManager.instances) == 1
            timeout_manager = FakeTimeoutManager.instances[0]
            assert timeout_manager.vm_ip == "192.168.56.10"
            assert timeout_manager.user == "tester"
            assert timeout_manager.session_id == "session123"

            await communicator.send_to(text_data="4.size,4.1280,4.1024;")
            await communicator.send_to(text_data="5.mouse,3.100,3.200,1.0;")
            await communicator.send_to(text_data="3.key,2.65,1.1;")
            await asyncio.sleep(0.05)

            assert timeout_manager.activity_updates == 2
            assert client.sent_messages == [
                "4.size,4.1280,4.1024;",
                "5.mouse,3.100,3.200,1.0;",
                "3.key,2.65,1.1;",
            ]
        finally:
            await communicator.disconnect()

        assert timeout_manager.is_active is False
        assert client.closed is True

    async def test_consumer_timeout_completes_analysis_and_closes_session(self, guac_consumer_app_factory, caplog):
        guac_consumer_app = guac_consumer_app_factory(
            timeout_manager_cls=ExpiringFakeTimeoutManager,
            stub_monitor_timeout=False,
        )
        caplog.set_level(logging.INFO, logger="guac-session")
        communicator = WebsocketCommunicator(
            guac_consumer_app,
            "/guac/websocket-tunnel/session_timeout/?guest_ip=192.168.56.11&vncport=5901&user=tester&recording_name=task-timeout",
            subprotocols=["guacamole"],
        )

        connected, subprotocol = await communicator.connect()
        assert connected is True
        assert subprotocol == "guacamole"

        assert len(FakeGuacamoleClient.instances) == 1
        client = FakeGuacamoleClient.instances[0]

        assert len(ExpiringFakeTimeoutManager.instances) == 1
        timeout_manager = ExpiringFakeTimeoutManager.instances[0]

        timeout_message = await asyncio.wait_for(communicator.receive_from(), timeout=1)
        assert timeout_message == "timeout.Session timed out due to inactivity;"

        close_event = await asyncio.wait_for(communicator.receive_output(), timeout=1)
        assert close_event["type"] == "websocket.close"

        await communicator.disconnect()
        await asyncio.wait_for(communicator.wait(), timeout=1)

        assert timeout_manager.complete_analysis_calls == 1
        assert timeout_manager.is_active is False
        assert client.closed is True
        assert "Session timeout detected for session_timeout, idle for 120001ms (threshold: 120000ms)" in caplog.text

    async def test_consumer_disconnect_cancels_reader_without_double_close(self, guac_consumer_app_factory):
        guac_consumer_app = guac_consumer_app_factory(read_guacd_impl=_cancel_then_close_read_guacd)
        communicator = WebsocketCommunicator(
            guac_consumer_app,
            "/guac/websocket-tunnel/session_disconnect/?guest_ip=192.168.56.12&vncport=5901&user=tester&recording_name=task-disconnect",
            subprotocols=["guacamole"],
        )

        connected, subprotocol = await communicator.connect()
        assert connected is True
        assert subprotocol == "guacamole"

        assert len(FakeGuacamoleClient.instances) == 1
        client = FakeGuacamoleClient.instances[0]

        assert len(FakeTimeoutManager.instances) == 1
        timeout_manager = FakeTimeoutManager.instances[0]

        await communicator.disconnect()
        await asyncio.wait_for(communicator.wait(), timeout=1)

        assert timeout_manager.is_active is False
        assert client.closed is True
