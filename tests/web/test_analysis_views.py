import pathlib
import random
from unittest import mock

import mongomock
import pymongo
import pytest
from django.test import SimpleTestCase

from lib.cuckoo.common.config import ConfigMeta
from modules.reporting.mongodb_constants import ANALYSIS_COLL, CALLS_COLL

TEST_DB_NAME = "cuckoo_test"


@pytest.fixture
def mongodb_enabled(custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "reporting.conf", "wt") as fil:
        print(f"[mongodb]\nenabled = yes\ndb = {TEST_DB_NAME}", file=fil)
    ConfigMeta.refresh()
    yield


@pytest.fixture
def mongodb_mock_client(request):
    with mongomock.patch(servers=(("127.0.0.1", 27017),)):
        client = pymongo.MongoClient(host=f"mongodb://127.0.0.1/{TEST_DB_NAME}")
        request.instance.mongo_client = client
        with mock.patch("dev_utils.mongodb.conn", new=client):
            yield


@pytest.mark.usefixtures("mongodb_enabled", "db", "mongodb_mock_client")
class TestAnalysisViews(SimpleTestCase):
    maxDiff = None

    def test_chunk_view_windows(self):
        """Exercise the chunk view."""
        # Populate mongo with some mock data:
        task_id = random.randint(1, 10000)
        pid = random.randint(1, 10000)
        chunk = 1
        category = "system"
        thread_id = random.randint(1, 10000)
        caller = f"{random.randint(0,10000):#04x}"
        parent_caller = f"{random.randint(0,10000):#04x}"
        api = "NtDelayExecution"
        calls = {
            "pid": pid,
            "calls": [
                {
                    "id": 1,
                    "category": category,
                    "timestamp": "2023-09-12 20:19:08,086",
                    "thread_id": f"{thread_id}",
                    "caller": caller,
                    "parentcaller": parent_caller,
                    "api": api,
                    "arguments": [],
                    "status": True,
                    "return": "0x00000000",
                    "repeated": 0,
                }
            ],
        }
        analysis = {
            "info": {
                "id": task_id,
                "machine": {
                    "platform": "windows",
                },
            },
            "behavior": {
                "processes": [
                    {
                        "process_id": pid,
                    }
                ]
            },
        }
        database = self.mongo_client[TEST_DB_NAME]
        calls_coll = database[CALLS_COLL]
        call = calls_coll.insert_one(calls)
        analysis_coll = database[ANALYSIS_COLL]
        analysis["behavior"]["processes"][0]["calls"] = [call.inserted_id]
        analysis_coll.insert_one(analysis)
        chunk_page = self.client.get(f"/analysis/chunk/{task_id}/{pid}/{chunk}/", headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertEqual(200, chunk_page.status_code, str(chunk_page))
        self.assertIsNotNone(chunk_page.content)
        content = chunk_page.content.decode()
        self.assertIn("Time</th>", content)
        self.assertIn("TID</th>", content)
        self.assertIn("API</th>", content)
        self.assertIn(f'class="{category}"', content)
        self.assertIn(f"<td>{thread_id}</td>", content)
        self.assertIn(f"<td>{caller}<br />{parent_caller}</td>", content)
        self.assertIn(f"<td><strong>{api}</strong></td>", content)

    def test_antivirus_view_windows(self):
        """Test the antivirus view."""
        # Populate mongo with some mock data:
        task_id = random.randint(1, 10000)
        k1, k2, k3 = "key1", "key2", "key3"
        v1, v2, v3 = "value1", "value2", "Clean"
        virustotal_resource = f"{random.randint(0,10000):#04x}"
        analysis = {
            "info": {
                "id": task_id,
                "category": "file",
                "machine": {
                    "platform": "windows",
                },
            },
            "target": {
                "category": "file",
                "file": {
                    "virustotal": {
                        "resource": virustotal_resource,
                        "scans": {
                            k1: {
                                "result": v1,
                            },
                            k2: {
                                "result": v2,
                            },
                            k3: {},
                        },
                    },
                },
            },
        }
        database = self.mongo_client[TEST_DB_NAME]
        analysis_coll = database[ANALYSIS_COLL]
        analysis_coll.insert_one(analysis)
        antivirus_page = self.client.get(f"/analysis/antivirus/{task_id}/")
        self.assertEqual(200, antivirus_page.status_code, str(antivirus_page))
        self.assertContains(antivirus_page, "VirusTotal")
        expected_url = f"https://www.virustotal.com/en/file/{virustotal_resource}/analysis/"
        self.assertContains(antivirus_page, expected_url)
        expected_results = [
            f'<td>{k1}</td><td><span class="text-danger">{v1}</span></td>',
            f'<td>{k2}</td><td><span class="text-danger">{v2}</span></td>',
            f'<td>{k3}</td><td><span class="text-muted">{v3}</span></td>',
        ]
        no_white_space = antivirus_page.content.decode().replace(" ", "").replace("\n", "").replace("spanclass", "span class")
        for item in expected_results:
            self.assertIn(item, no_white_space)
