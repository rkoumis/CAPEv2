# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pathlib
import random
import sys
import tempfile
from unittest import mock

import httpretty
import mongomock
import pymongo
import pytest
from mongoengine import connect, disconnect

from lib.cuckoo.common.config import ConfigMeta
from lib.cuckoo.common.path_utils import path_delete, path_write_file
from lib.cuckoo.common.web_utils import _download_file, force_int, get_file_content, parse_request_arguments
from modules.reporting.mongodb_constants import ANALYSIS_COLL, DB_ALIAS

TEST_DB_NAME = "cuckoo_test_db"


@pytest.fixture
def mongodb_enabled(custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "reporting.conf", "wt") as fil:
        print(f"[mongodb]\nenabled = yes\ndb = {TEST_DB_NAME}", file=fil)
    ConfigMeta.refresh()
    yield


@pytest.fixture
def mongodb_mock_client():
    with mongomock.patch(servers=(("127.0.0.1", 27017),)):
        client = pymongo.MongoClient(host=f"mongodb://127.0.0.1/{TEST_DB_NAME}")
        connect(TEST_DB_NAME, alias=DB_ALIAS, host="mongodb://localhost", mongo_client_class=mongomock.MongoClient)
        with mock.patch("dev_utils.mongodb.conn", new=client):
            yield client
            disconnect(alias=DB_ALIAS)


@pytest.fixture
def paths():
    path_list = []
    for i in range(3):
        path_list += [tempfile.NamedTemporaryFile(delete=False).name]
        _ = path_write_file(path_list[i], str(i + 10), mode="text")
    yield path_list
    try:
        for i in path_list:
            path_delete(i)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


@pytest.fixture
def path():
    onepath = tempfile.NamedTemporaryFile(delete=False)
    _ = path_write_file(onepath.name, "1338", mode="text")
    yield onepath.name
    try:
        path_delete(onepath.name)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


def test_get_file_content(paths):
    assert get_file_content(paths) == b"10"


def test_get_file_contents_path(path):
    assert get_file_content(path) == b"1338"


@httpretty.activate
def test__download_file():
    httpretty.register_uri(httpretty.GET, "http://mordor.eye/onering", body="frodo")
    assert _download_file(route=None, url="http://mordor.eye/onering", options="dne_abc=123,dne_def=456") == b"frodo"


@pytest.fixture
def mock_request():
    class MockReq:
        POST = {"clock": "03-31-2021 14:24:36"}

    yield MockReq()


def test_parse_request_arguments(mock_request):
    ret = parse_request_arguments(mock_request)

    assert ret == (
        "",
        "",
        0,
        0,
        "",
        "",
        "",
        None,
        "",
        False,
        "03-31-2021 14:24:36",
        False,
        None,
        None,
        None,
        None,
        False,
        None,
        None,
        None,
        "",
        "",
    )


def test_force_int():
    assert force_int(value="1") == 1
    assert force_int(value="$") == 0


def test_perform_search_invalid_ttp():
    sys.modules.pop("lib.cuckoo.common.web_utils", None)
    from lib.cuckoo.common.web_utils import perform_search

    with pytest.raises(ValueError) as exc:
        _ = perform_search(term="ttp", value="SPOONS")
    assert "Invalid TTP" in str(exc)


def test_perform_search_not_in_search_term_map():
    sys.modules.pop("lib.cuckoo.common.web_utils", None)
    from lib.cuckoo.common.web_utils import perform_search, search_term_map

    term = "Unexpected"
    assert term not in search_term_map
    actual_result = perform_search(term=term, value="not in search term map")
    assert actual_result is None


def test_perform_search_invalid_int_value():
    sys.modules.pop("lib.cuckoo.common.web_utils", None)
    from lib.cuckoo.common.web_utils import normalized_int_terms, perform_search

    term = random.choice(normalized_int_terms)
    non_integer_value = "not an integer"
    with pytest.raises(ValueError) as exc:
        _ = perform_search(term=term, value=non_integer_value)
    assert non_integer_value in str(exc)


@pytest.mark.usefixtures("mongodb_enabled")
def test_perform_search_mongo(mongodb_mock_client):
    sys.modules.pop("lib.cuckoo.common.web_utils", None)
    from lib.cuckoo.common.web_utils import perform_search, search_term_map

    term = "tlp"
    value = "red"
    assert term in search_term_map
    assert search_term_map[term] == "info.tlp"
    id = random.randint(1, 1000)
    analysis = {
        "info": {
            "id": id,
            term: value,
        }
    }
    mongodb_mock_client[TEST_DB_NAME][ANALYSIS_COLL].insert_one(analysis)
    result = perform_search(term=term, value=value)
    assert len(result) == 1
    assert result[0]["info"][term] == value
    assert result[0]["info"]["id"] == id
