"""Utilities for Guacamole protocol handling and activity detection."""

from typing import Optional

# Guacamole uses a length-prefixed element format:
#   <len>.<value>[,<len>.<value>...];
# Example mouse instruction: 5.mouse,3.100,3.200,1.0;
#
# We only need to extract the instruction name (first element) to decide
# whether the message represents user-driven input.
ACTIVITY_INSTRUCTIONS = frozenset({"key", "mouse"})


def _parse_first_element(message: str, start: int) -> tuple[Optional[str], int]:
    """Return the first element of the instruction starting at *start* and the
    index of the character immediately after the element separator (',' or ';').
    Returns ``(None, -1)`` on any parse failure."""
    dot = message.find(".", start)
    if dot == -1:
        return None, -1
    length_text = message[start:dot]
    if not length_text.isdigit():
        return None, -1
    length = int(length_text)
    value_end = dot + 1 + length
    if value_end > len(message):
        return None, -1
    return message[dot + 1 : value_end], value_end


def is_user_activity(message: str) -> bool:
    """Return ``True`` if *message* contains a mouse or keyboard instruction.

    Scans through potentially multiple concatenated Guacamole instructions and
    returns as soon as one activity instruction is found.
    """
    if not message or not isinstance(message, str):
        return False

    try:
        idx = 0
        msg_len = len(message)
        while idx < msg_len:
            name, after = _parse_first_element(message, idx)
            if name is None:
                return False
            # The element must be followed by a separator (',' or ';') to be
            # part of a well-formed instruction.
            if after >= msg_len or message[after] not in (",", ";"):
                return False
            # Find the end of this instruction
            semi = message.find(";", after)
            if semi == -1:
                return False
            if name in ACTIVITY_INSTRUCTIONS:
                return True
            idx = semi + 1
        return False
    except Exception:
        return False


def extract_session_info(query_params: dict) -> tuple[Optional[str], Optional[str]]:
    """Extract VM IP and user information from WebSocket query parameters."""
    vm_ip = query_params.get("guest_ip", [None])[0] if query_params.get("guest_ip") else None
    user = query_params.get("user", ["unknown_user"])[0] if query_params.get("user") else "unknown_user"
    return vm_ip, user
