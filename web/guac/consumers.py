import asyncio
import logging
import urllib.parse

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from guacamole.client import GuacamoleClient

# Ensure this import path matches your project structure
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.guac_utils import extract_session_info, is_user_activity

from .timeout_manager import SessionTimeoutManager

logger = logging.getLogger("guac-session")
web_cfg = Config("web")


class GuacamoleWebSocketConsumer(AsyncWebsocketConsumer):
    # Channels 4: Explicitly declare supported subprotocols
    subprotocols = ["guacamole"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = None
        self.task = None
        self.is_closing = False
        self.timeout_manager = None
        self.timeout_task = None
        self._disconnect_seen = False
        self._close_sent = False
        self._close_lock = asyncio.Lock()

    async def _close_websocket(self):
        """Close the websocket at most once across all concurrent code paths."""
        async with self._close_lock:
            if self._close_sent or self._disconnect_seen:
                return

            self._close_sent = True

        try:
            await self.close()
        except RuntimeError as error:
            if "Unexpected ASGI message 'websocket.close'" in str(error):
                logger.debug("Suppressing duplicate websocket.close for session")
                return
            raise

    async def connect(self):
        """
        Initiate the GuacamoleClient and create a connection to it.
        """
        try:
            # Capture session_id from URL route for logging context
            session_id = self.scope["url_route"]["kwargs"].get("session_id", "unknown")

            # 1. Parse Configuration & Parameters inside a try block
            # This prevents 500 errors from reaching the client as HTML
            guacd_hostname = web_cfg.guacamole.guacd_host or "localhost"
            guacd_port = int(web_cfg.guacamole.guacd_port) or 4822
            guacd_recording_path = web_cfg.guacamole.guacd_recording_path or ""
            guest_protocol = web_cfg.guacamole.guest_protocol or "vnc"
            guest_width = int(web_cfg.guacamole.guest_width) or 1280
            guest_height = int(web_cfg.guacamole.guest_height) or 1024
            guest_username = web_cfg.guacamole.username or ""
            guest_password = web_cfg.guacamole.password or ""

            # Safe decoding of query string
            query_string = self.scope.get("query_string", b"").decode()
            params = urllib.parse.parse_qs(query_string)

            if "rdp" in guest_protocol:
                hosts = params.get("guest_ip", [""])
                guest_host = hosts[0]
                guest_port = int(web_cfg.guacamole.guest_rdp_port) or 3389
                ignore_cert = "true" if web_cfg.guacamole.ignore_rdp_cert is True else "false"

                # RDP Performance Optimizations
                # Default to safe/fast values if not present in config
                disable_wallpaper = "true" if getattr(web_cfg.guacamole, "rdp_disable_wallpaper", "yes") == "yes" else "false"
                disable_theming = "true" if getattr(web_cfg.guacamole, "rdp_disable_theming", "yes") == "yes" else "false"
                enable_font_smoothing = "true" if getattr(web_cfg.guacamole, "rdp_enable_font_smoothing", "no") == "yes" else "false"
                enable_full_window_drag = "true" if getattr(web_cfg.guacamole, "rdp_enable_full_window_drag", "no") == "yes" else "false"
                enable_desktop_composition = "true" if getattr(web_cfg.guacamole, "rdp_enable_desktop_composition", "no") == "yes" else "false"
                enable_menu_animations = "true" if getattr(web_cfg.guacamole, "rdp_enable_menu_animations", "no") == "yes" else "false"
                enable_audio = "audio" if getattr(web_cfg.guacamole, "enable_audio", "no") == "yes" else None

                extra_args = {
                    "disable-wallpaper": disable_wallpaper,
                    "disable-theming": disable_theming,
                    "enable-font-smoothing": enable_font_smoothing,
                    "enable-full-window-drag": enable_full_window_drag,
                    "enable-desktop-composition": enable_desktop_composition,
                    "enable-menu-animations": enable_menu_animations,
                }
                if enable_audio:
                    extra_args["enable-audio"] = "true"

            else:
                guest_host = web_cfg.guacamole.vnc_host or "localhost"
                ports = params.get("vncport", ["5900"])
                guest_port = int(ports[0])
                ignore_cert = "false"

                # VNC Performance Optimizations
                vnc_color_depth = str(getattr(web_cfg.guacamole, "vnc_color_depth", 16))
                vnc_cursor = getattr(web_cfg.guacamole, "vnc_cursor", "local")

                extra_args = {
                    "color-depth": vnc_color_depth,
                    "cursor": vnc_cursor,
                }

            guacd_recording_name = params.get("recording_name", ["task-recording"])[0]
            task_id = params.get("task_id", [None])[0]

            # 2. Connect to Guacamole Daemon (guacd)
            self.client = GuacamoleClient(guacd_hostname, guacd_port)

            await sync_to_async(self.client.handshake)(
                protocol=guest_protocol,
                width=guest_width,
                height=guest_height,
                hostname=guest_host,
                port=guest_port,
                username=guest_username,
                password=guest_password,
                recording_path=guacd_recording_path,
                recording_name=guacd_recording_name,
                ignore_cert=ignore_cert,
                **extra_args,
            )

            if self.client.connected:
                # 3. Accept the WebSocket connection specifically for 'guacamole'
                # Accept first to ensure the channel is open before sending data
                await self.accept(subprotocol="guacamole")
                logger.info("Guacamole connection accepted for session %s.", session_id)

                # 4. Initialize timeout handling
                try:
                    vm_ip, user = extract_session_info(params)

                    if not vm_ip:
                        vm_ip = guest_host if "guest_host" in locals() else None

                    self.timeout_manager = SessionTimeoutManager(
                        vm_ip=vm_ip or "unknown",
                        user=user or "unknown_user",
                        session_id=session_id,
                        task_id=task_id,
                    )
                except Exception as e:
                    logger.error("Failed to initialize timeout manager: %s", e)
                    self.timeout_manager = None

                # 5. Start the background tasks
                self.task = asyncio.create_task(self.read_guacd())
                if self.timeout_manager and self.timeout_manager.idle_timeout_ms > 0:
                    self.timeout_task = asyncio.create_task(self.monitor_timeout())
            else:
                logger.warning("Guacamole handshake failed. Closing connection.")
                self.is_closing = True
                await self._close_websocket()

        except Exception as e:
            logger.error("Error during Guacamole connect: %s", str(e))
            self.is_closing = True
            await self._close_websocket()

    async def disconnect(self, code):
        """
        Close the GuacamoleClient connection on WebSocket disconnect.
        """
        # Set flag to prevent double close
        self.is_closing = True
        self._disconnect_seen = True

        if self.timeout_manager:
            self.timeout_manager.set_inactive()

        tasks_to_cancel = []
        # Cancel the reader task if it exists
        if self.task:
            tasks_to_cancel.append(self.task)
        if self.timeout_task:
            tasks_to_cancel.append(self.timeout_task)

        for t in tasks_to_cancel:
            t.cancel()
        for t in tasks_to_cancel:
            try:
                await t
            except asyncio.CancelledError:
                pass

        # Close the client safely
        if self.client:
            try:
                await sync_to_async(self.client.close)()
            except Exception as e:
                logger.error("Error closing guacamole client: %s", str(e))

    async def receive(self, text_data=None, bytes_data=None):
        """
        Handle data received in the WebSocket, send to GuacamoleClient.
        """
        if text_data and self.client:
            # logger.debug("To server: %s", text_data) # Verbose logging can slow down RDP
            if self.timeout_manager and is_user_activity(text_data):
                self.timeout_manager.update_activity()

            try:
                await sync_to_async(self.client.send)(text_data)
            except Exception as e:
                logger.error("Failed to send data to guacd: %s", str(e))

    async def read_guacd(self):
        """
        Receive data from GuacamoleClient and pass it to the WebSocket
        """
        try:
            while True:
                # This blocks in a thread, releasing the async loop
                # thread_sensitive=False allows this to run in a separate thread pool, not blocking the main thread
                content = await sync_to_async(self.client.receive, thread_sensitive=False)()
                if content:
                    # logger.debug("From server: %s", content)
                    await self.send(text_data=content)
                else:
                    break
        except asyncio.CancelledError:
            pass  # Task cancellation is normal on disconnect
        except Exception as e:
            logger.error("Exception in Guacamole message loop: %s", e)
        finally:
            # Only close the websocket if we haven't already started closing
            await self._close_websocket()

    async def monitor_timeout(self):
        """
        Monitor session for idle timeout and handle cleanup when timeout occurs.
        """
        try:
            while self.timeout_manager and self.timeout_manager.is_active and not self.is_closing:
                await asyncio.sleep(self.timeout_manager.activity_check_interval)

                if not self.timeout_manager or not self.timeout_manager.is_active:
                    break

                if self.timeout_manager.is_timed_out():
                    idle_time = self.timeout_manager.get_idle_time_ms()
                    logger.info(
                        "Session timeout detected for %s, idle for %sms (threshold: %sms)",
                        self.timeout_manager.session_id,
                        idle_time,
                        self.timeout_manager.idle_timeout_ms,
                    )

                    await self.handle_timeout()
                    break
                else:
                    idle_time = self.timeout_manager.get_idle_time_ms()
                    logger.debug("Session %s idle for %sms", self.timeout_manager.session_id, idle_time)

        except asyncio.CancelledError:
            logger.debug("Timeout monitor cancelled for session %s", getattr(self.timeout_manager, "session_id", "unknown"))
        except Exception as e:
            logger.error("Error in timeout monitor: %s", str(e))

    async def handle_timeout(self):
        """
        Handle session timeout by signalling analysis completion and closing the connection.
        """
        if not self.timeout_manager:
            return

        try:
            logger.info(
                "Handling timeout for session %s, VM: %s",
                self.timeout_manager.session_id,
                self.timeout_manager.vm_ip,
            )
            success = await self.timeout_manager.complete_analysis()
            if success:
                logger.info("Successfully signalled analysis complete for %s", self.timeout_manager.vm_ip)
            else:
                logger.warning("Failed to signal analysis complete for %s", self.timeout_manager.vm_ip)

            try:
                await self.send(text_data="timeout.Session timed out due to inactivity;")
            except Exception as e:
                logger.warning("Could not send timeout message to client: %s", e)

        except Exception as e:
            logger.error("Error handling session timeout: %s", e)
        finally:
            if not self.is_closing:
                await self._close_websocket()
