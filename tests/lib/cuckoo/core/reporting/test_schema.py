"""Tests for the schema definition."""
from lib.cuckoo.core.reporting.schema import Behavior


def test_nested_behavior_objects():
    process_id = 123
    process_call = {"oid": "the_process_oid"}
    process = {"process_id": process_id, "calls": [process_call]}
    behavior_dict = {"processes": [process]}
    behavior = Behavior(**behavior_dict)
    assert behavior.processes[0].process_id == process_id
    assert behavior.processes[0].calls[0].oid == "the_process_oid"
