"""Tests for the schema definition."""
import datetime
import random

from lib.cuckoo.core.reporting import schema


def test_nested_behavior_objects():
    process_id = random.randint(0, 100)
    call_id = random.randint(0, 100)
    process_call = {"id": call_id, "oid": "the_process_oid"}
    process = {"process_id": process_id, "calls": [process_call]}
    behavior_dict = {"processes": [process]}
    behavior = schema.Behavior(**behavior_dict)
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
    call = schema.Call(**call_dict)
    assert call.thread_id == int(thread_id)
    assert isinstance(call.arguments[0], schema.Call.Argument)
    assert call.arguments[0].name == "name1"
    assert call.arguments[0].value == "value1"
    assert call.arguments[0].pretty_value is None
    assert call.arguments[1].name == "name2"
    assert call.arguments[1].value == "value2"
    assert call.arguments[1].pretty_value == "pretty value2"


def test_analysis_config_object():
    hash_group = dict(
        md5=f"{random.randint(0, 100000000):X}",
        sha1=f"{random.randint(0, 100000000):X}",
        sha256=f"{random.randint(0, 100000000):X}",
        sha512=f"{random.randint(0, 100000000):X}",
        sha3_384=f"{random.randint(0, 100000000):X}",
    )
    the_family = dict(SomeKey="SomeValue")
    the_dict = dict(
        _associated_config_hashes=[hash_group],
        _associated_analysis_hashes=hash_group,
        SomeFamily=the_family,
    )
    analysis_config = schema.AnalysisConfig(**the_dict)
    assert isinstance(analysis_config, schema.AnalysisConfig)
    assert isinstance(analysis_config.associated_config_hashes[0], schema.AnalysisConfig.HashGroup)
    assert analysis_config.associated_analysis_hashes.model_dump() == hash_group
    expected_keys = ["_associated_config_hashes", "_associated_analysis_hashes", "SomeFamily"]
    assert expected_keys == list(analysis_config.model_dump(by_alias=True).keys())
    expected_keys = ["associated_config_hashes", "associated_analysis_hashes", "SomeFamily"]
    assert expected_keys == list(analysis_config.model_dump().keys())


def test_network_object():
    """Ensure the Network object is populated correctly."""
    the_dict = {
        "pcap_sha256": f"{random.randint(0, 100000000):X}",
        "dns": [
            {
                "request": "google.com",
                "type": "A",
                "first_seen": 1732561543.679787,
            },
        ],
        "http": [
            {
                "user-agent": "Mozilla/5.0",
            },
        ],
    }
    network = schema.Network(**the_dict)
    assert isinstance(network, schema.Network)
    assert isinstance(network.dns[0].first_seen, datetime.datetime)
    assert network.dns[0].request == "google.com"
    assert network.http[0].user_agent == "Mozilla/5.0"


def test_nested_machine():
    """Ensure we can populate the Info schema."""
    the_dict = {
        "machine": {"started_on": "2025-02-07 17:20:11", "shutdown_on": "2025-02-07 17:20:56"},
        "version": "2.42",
        "started": "2025-02-07 17:20:11",
        "ended": "2025-02-07 17:20:58",
        "duration": 42,
        "id": 123456,
        "category": "file",
    }
    the_info = schema.Info(**the_dict)
    assert isinstance(the_info, schema.Info)
    assert isinstance(the_info.startedn, datetime.datetime)
    assert isinstance(the_info.machine.started_on, datetime.datetime)
