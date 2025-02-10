import functools
import inspect
import pathlib

from lib.cuckoo.core.reporting import schema
import mongomock
import pymongo
import pytest
from bson.objectid import ObjectId

from lib.cuckoo.common import config
from lib.cuckoo.common.config import ConfigMeta
from lib.cuckoo.core.reporting.backends import mongodb

TEST_DB_NAME = "cuckoo_test_db"
TEST_TASK_IDS = (42, 43, 44)
TEST_PIDS = (1, 2, 3, 4, 5)

getfunctions = functools.partial(inspect.getmembers, predicate=inspect.isfunction)


@pytest.fixture
def mongodb_config(request, custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "reporting.conf", "wt") as fil:
        print(f"[mongodb]\nenabled = yes\ndb = {TEST_DB_NAME}", file=fil)
    ConfigMeta.refresh()
    reporting_cfg = config.Config("reporting")
    request.instance.cfg = reporting_cfg
    yield reporting_cfg


@pytest.fixture
def elasticsearch_config(request, custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "reporting.conf", "wt") as fil:
        print(f"[elasticsearch]\nenabled = yes\ndb = {TEST_DB_NAME}", file=fil)
    ConfigMeta.refresh()
    reporting_cfg = config.Config("reporting")
    request.instance.cfg = reporting_cfg
    yield reporting_cfg


@pytest.fixture
def mongodb_mock_client(request):
    with mongomock.patch(servers=(("127.0.0.1", 27017),)):
        client = pymongo.MongoClient(host=f"mongodb://127.0.0.1/{TEST_DB_NAME}")
        request.instance.mongo_client = client
        yield client


@pytest.fixture
def mongodb_populate_test_data(mongodb_mock_client):
    # TODO find a nicer way to populate mongo with test data

    database = mongodb_mock_client[TEST_DB_NAME]
    analysis_collection = database[mongodb.ANALYSIS_COLLECTION]
    calls_collection = database[mongodb.CALLS_COLLECTION]

    machine = {
        "id": 28033,
        "status": "stopping",
        "name": "windows-machine-1",
        "label": "windows-machine-label",
        "platform": "windows",
        "manager": "KVM",
        "started_on": "2024-03-29 14:00:26",
        "shutdown_on": "2024-03-29 14:04:20",
    }
    info = {
        "id": 1,
        "machine": machine,
        "category": "file"
    }
    calls = [
        {
            "pid": _pid,
            "calls": [
                {
                    "timestamp": "2024-11-19 14:33:38,985",
                    "thread_id": "6716",
                    "caller": "0x00401e03",
                    "parentcaller": "0x00401fc1",
                    "category": "process",
                    "api": "SomeApiCall",
                    "status": bool(_id - 1),
                    "return": "0x00000000",
                    "arguments": [
                        {"name": "SomeArgument", "value": "0xffffffff"},
                    ],
                    "repeated": 0,
                    "id": _id * _pid,
                }
                for _id in range(1, _pid + 1)
            ],
        }
        for _pid in TEST_PIDS
    ]

    call_ids = calls_collection.insert_many(calls).inserted_ids

    procs = [
        {
            "process_id": 4380,
            "process_name": "explorer.exe",
            "parent_id": 4344,
            "module_path": "C:\\Windows\\explorer.exe",
            "first_seen": "2024-11-13 16:55:42,645",
            "calls": call_ids,
            "threads": [
                "4340",
                "1460",
            ],
            "environ": {
                "UserName": "user",
                "ComputerName": "DESKTOP-DESKTOP",
                "WindowsPath": "C:\\Windows",
                "TempPath": "C:\\Users\\user\\AppData\\Local\\Temp\\",
                "CommandLine": "C:\\Windows\\Explorer.EXE",
                "RegisteredOwner": "",
                "RegisteredOrganization": "",
                "ProductName": "",
                "SystemVolumeSerialNumber": "ue4m-dzwd",
                "SystemVolumeGUID": "85fmrfbw-0000-0000-0000-100000000000",
                "MachineGUID": "",
                "MainExeBase": "0x7ff702250000",
                "MainExeSize": "0x004fd000",
                "Bitness": "64-bit",
            },
            "file_activities": {"read_files": [], "write_files": [], "delete_files": []},
        }
    ]
    behavior = {
        "processes": procs,
        "anomaly": [],
        "processtree": [],
        "summary": {
            "files": ["files"],
            "delete_files": ["deletedfiles"],
            "keys": ["key"],
            "read_keys": ["readkey"],
            "write_keys": ["writekey"],
            "delete_keys": ["deletekey"],
            "executed_commands": ["excutedcommand.exe"],
            "resolved_apis": ["ResolvedApi"],
            "mutexes": ["mutex"],
            "created_services": ["createdsvc"],
            "started_services": ["startedsvc"],
        },
    }
    configs = [
        {
            "BadMalware": {"domain": [["example.com"]]},
            "_associated_config_hashes": [
                {"md5": "a" * 32, "sha1": "a" * 40, "sha256": "a" * 64, "sha512": "a" * 128, "sha3_384": "a" * 96},
                {"md5": "b" * 32, "sha1": "b" * 40, "sha256": "b" * 64, "sha512": "b" * 128, "sha3_384": "b" * 96},
            ],
            "_associated_analysis_hashes": {
                "md5": "a" * 32,
                "sha1": "a" * 40,
                "sha256": "a" * 64,
                "sha512": "a" * 128,
                "sha3_384": "a" * 96,
            },
        }
    ]

    analysis = {
        "info": info,
        "CAPE": {"configs": configs},
        "target": {
            "file": {
                "virustotal": {
                    "summary": "66/76",
                },
                "clamav": [],
                "file_ref": "a"*64
            },
        },
        "url": {
            "virustotal": {
                "summary": "20/30",
            }
        },
        "detections": [
            {
                "family": "Robinson",
                "details": [
                    {"VirusTotal": "bbbbbbbbbbbbbbbbbbbb"},
                ],
            }
        ],
        "network": schema.Network(pcap_sha256="PCAP"*16).model_dump(),
        "behavior": behavior,
        "suricata": {
            "http": ["example.com"]
        },
        "suri_tls_cnt": 6,
        "suri_alert_cnt": 17,
        "suri_http_cnt": 210,
        "trid": 17,
        "ensure_extra_fields": "are_allowed",
    }

    for task_id in TEST_TASK_IDS:
        analysis["_id"] = ObjectId()
        analysis["info"]["id"] = task_id
        analysis_collection.insert_one(analysis)
