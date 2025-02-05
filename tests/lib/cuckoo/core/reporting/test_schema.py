"""Tests for the schema definition."""
import random

from lib.cuckoo.core.reporting.schema import Behavior, Call


def test_nested_behavior_objects():
    process_id = random.randint(0, 100)
    call_id = random.randint(0, 100)
    process_call = {"id": call_id, "oid": "the_process_oid"}
    process = {"process_id": process_id, "calls": [process_call]}
    behavior_dict = {"processes": [process]}
    behavior = Behavior(**behavior_dict)
    assert behavior.processes[0].process_id == process_id
    assert behavior.processes[0].calls[0].oid == "the_process_oid"
    assert behavior.processes[0].calls[0].id == call_id


def test_call_argument_object():
    id = random.randint(0, 10000)
    thread_id = str(random.randint(0, 10000))
    arguments = [
        {"name": "name1", "value": "value1"},
        {"name": "name2", "value": "value2", "pretty_value": "pretty value2"},
    ]
    call_dict = {"id": id, "thread_id": thread_id, "arguments": arguments, "timestamp": "2024-12-25 09:09:09"}
    call = Call(**call_dict)
    assert call.thread_id == int(thread_id)
    assert isinstance(call.arguments[0], Call.Argument)
    assert call.arguments[0].name == "name1"
    assert call.arguments[0].value == "value1"
    assert call.arguments[0].pretty_value is None
    assert call.arguments[1].name == "name2"
    assert call.arguments[1].value == "value2"
    assert call.arguments[1].pretty_value == "pretty value2"
