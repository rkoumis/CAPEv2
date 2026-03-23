"""Utilities for Guacamole protocol handling and activity detection."""

from typing import Iterator, Optional


class GuacamoleActivityDetector:
    """Detects user activity in Guacamole protocol messages."""

    # User-driven instructions that should reset the idle timer.
    ACTIVITY_INSTRUCTIONS = {"clipboard", "key", "mouse", "touch"}

    # Minimum argument counts for valid user-driven instructions, excluding the
    # instruction name itself.
    MIN_ARGUMENTS = {
        "clipboard": 1,
        "key": 2,
        "mouse": 3,
        "touch": 7,
    }

    @classmethod
    def iter_instructions(cls, message: str) -> Iterator[list[str]]:
        """
        Yield decoded Guacamole instructions from a raw protocol payload.

        Guacamole uses a length-prefixed element format:

            <len>.<value>[,<len>.<value>...];

        Example mouse move instruction:

            5.mouse,3.100,3.200,1.0;
        """
        if not message or not isinstance(message, str):
            return

        index = 0
        message_length = len(message)

        while index < message_length:
            elements = []

            while True:
                dot_index = message.find(".", index)
                if dot_index == -1:
                    return

                element_length_text = message[index:dot_index]
                if not element_length_text.isdigit():
                    return

                element_length = int(element_length_text)
                element_start = dot_index + 1
                element_end = element_start + element_length
                if element_end > message_length:
                    return

                elements.append(message[element_start:element_end])
                index = element_end
                if index >= message_length:
                    return

                separator = message[index]
                index += 1

                if separator == ";":
                    break

                if separator != ",":
                    return

            if elements:
                yield elements

    @classmethod
    def is_user_activity(cls, message: str) -> bool:
        """
        Analyze a raw Guacamole protocol payload to determine whether it
        contains a valid user-initiated instruction.
        """
        if not message or not isinstance(message, str):
            return False

        try:
            for instruction in cls.iter_instructions(message):
                instruction_name = instruction[0]

                if instruction_name not in cls.ACTIVITY_INSTRUCTIONS:
                    continue

                minimum_argument_count = cls.MIN_ARGUMENTS[instruction_name]
                if len(instruction) - 1 >= minimum_argument_count:
                    return True

            return False

        except Exception:
            return False

    @classmethod
    def extract_session_info(cls, query_params: dict) -> tuple[Optional[str], Optional[str]]:
        """Extract VM IP and user information from WebSocket query parameters."""
        vm_ip = query_params.get("guest_ip", [None])[0] if query_params.get("guest_ip") else None
        user = query_params.get("user", ["unknown_user"])[0] if query_params.get("user") else "unknown_user"
        return vm_ip, user
