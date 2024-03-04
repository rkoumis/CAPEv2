"""Tests for the agent."""
import datetime
import io
import multiprocessing
import os
import pathlib
import random
import sys
import tempfile
import time
import uuid
import zipfile
from urllib.parse import urljoin

import requests

import agent

HOST = "127.0.0.1"
PORT = 8000
BASE_URL = f"http://{HOST}:{PORT}"

DIRPATH = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))


def make_temp_name():
    return str(uuid.uuid4())


class TestAgent:
    """Test the agent API."""

    agent_process: multiprocessing.Process = None

    def setup_method(self):
        agent.state = {"status": agent.Status.INIT, "description": "", "async_subprocess": None}
        ev = multiprocessing.Event()
        self.agent_process = multiprocessing.Process(
            target=agent.app.run,
            kwargs={"host": HOST, "port": PORT, "event": ev},
        )
        self.agent_process.start()

        # wait for http server to start
        if not ev.wait(5.0):
            raise Exception("Failed to start agent HTTP server")

        # create temp directory for tests, as makes tidying up easier
        form = {"dirpath": DIRPATH, "mode": 0o777}
        r = requests.post(f"{BASE_URL}/mkdir", data=form)
        assert r.status_code == 200
        assert r.json()["message"] == "Successfully created directory"
        assert os.path.isdir(DIRPATH)

    def teardown_method(self):
        # remove the temporary directory and files
        form = {"path": DIRPATH}
        js = self.post_form("remove", form)
        assert js["message"] == "Successfully deleted directory"
        try:
            # shut down the agent service, which tests the kill endpoint
            r = requests.get(f"{BASE_URL}/kill")
            assert r.status_code == 200
            assert r.json()["message"] == "Quit the CAPE Agent"
        except requests.exceptions.ConnectionError:
            pass
        assert not os.path.isdir(DIRPATH)

        # clean up the multiprocessing stuff
        self.agent_process.join()
        self.agent_process.close()

    @staticmethod
    def non_existent_directory():
        root = pathlib.Path(tempfile.gettempdir()).root
        current_pid = os.getpid()
        non_existent = pathlib.Path(root, str(current_pid), str(random.randint(10000, 99999)))
        assert not os.path.isdir(non_existent)
        assert not os.path.exists(non_existent)
        return non_existent

    @staticmethod
    def get_status(expected_status=200):
        """Do a get and check the status"""
        status_url = urljoin(BASE_URL, "status")
        r = requests.get(status_url)
        js = r.json()
        assert js["message"] == "Analysis status"
        assert r.status_code == expected_status
        return js

    @staticmethod
    def store_file(file_contents):
        """Store a file with the given contents. Return the filepath."""
        sep = os.linesep
        upload_file = {"file": ("test.py", sep.join(file_contents))}
        filepath = os.path.join(DIRPATH, make_temp_name() + ".py")
        form = {"filepath": filepath}
        store_url = urljoin(BASE_URL, "store")
        r = requests.post(store_url, files=upload_file, data=form)
        assert r.status_code == 200
        assert os.path.isfile(filepath)
        return filepath

    @staticmethod
    def post_form(url_part, form_data, expected_status=200):
        """Post to the URL and return the json."""
        url = urljoin(BASE_URL, url_part)
        r = requests.post(url, data=form_data)
        assert r.status_code == expected_status
        js = r.json()
        return js

    def test_root(self):
        r = requests.get(f"{BASE_URL}/")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "CAPE Agent!"
        assert "version" in js
        assert "features" in js
        assert "execute" in js["features"]
        assert "execpy" in js["features"]
        assert "pinning" in js["features"]

    def test_status_write_valid_text(self):
        """Write a status of 'exception'."""
        form = {"status": "exception"}
        url_part = "status"
        _ = self.post_form(url_part, form)
        js = self.get_status()
        assert js["status"] == "exception"

    def test_status_write_valid_number(self):
        """Write a status of '5'."""
        form = {"status": 5}
        url_part = "status"
        _ = self.post_form(url_part, form)
        js = self.get_status()
        assert js["status"] == "exception"

    def test_status_write_invalid(self):
        """Fail to provide a valid status."""
        form = {"description": "Test Status"}
        js = self.post_form("status", form, 400)
        assert js["message"] == "No valid status has been provided"

        form = {"status": "unexpected value"}
        r = requests.post(f"{BASE_URL}/status", data=form)
        js = self.post_form("status", form, 400)
        assert js["message"] == "No valid status has been provided"

    def test_logs(self):
        """Test that the agent responds to a request for the logs."""
        r = requests.get(f"{BASE_URL}/logs")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Agent logs"
        assert "stdout" in js
        assert "stderr" in js

    def test_system(self):
        """Test that the agent responds to a request for the system/platform."""
        r = requests.get(f"{BASE_URL}/system")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "System"
        assert "system" in js
        if sys.platform == "win32":
            assert js["system"] == "Windows"
        else:
            assert js["system"] == "Linux"

    def test_environ(self):
        """Test that the agent responds to a request for the environment."""
        r = requests.get(f"{BASE_URL}/environ")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Environment variables"
        assert "environ" in js

    def test_path(self):
        """Test that the agent responds to a request for its path."""
        r = requests.get(f"{BASE_URL}/path")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Agent path"
        assert "filepath" in js
        assert os.path.isfile(js["filepath"])

    def test_pinning(self):
        r = requests.get(f"{BASE_URL}/pinning")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully pinned Agent"
        assert "client_ip" in js

        # Pinning again causes an error.
        r = requests.get(f"{BASE_URL}/pinning")
        assert r.status_code == 500
        js = r.json()
        assert js["message"] == "Agent has already been pinned to an IP!"

    def test_mkdir_valid(self):
        """Test that the agent creates a directory."""
        new_dir = os.path.join(DIRPATH, make_temp_name())
        form = {
            "dirpath": new_dir,
            "mode": 0o777,
        }
        js = self.post_form("mkdir", form)
        assert js["message"] == "Successfully created directory"
        assert os.path.exists(new_dir)
        assert os.path.isdir(new_dir)

    def test_mkdir_invalid(self):
        form = {}
        js = self.post_form("mkdir", form, 400)
        assert js["message"] == "No dirpath has been provided"

        root = pathlib.Path(tempfile.gettempdir()).root
        form = {"dirpath": root, "mode": 0o777}
        js = self.post_form("mkdir", form, 500)
        assert js["message"] == "Error creating directory"

    def test_mktemp_valid(self):
        form = {
            "dirpath": DIRPATH,
            "prefix": make_temp_name(),
            "suffix": "tmp",
        }
        js = self.post_form("mktemp", form)
        assert js["message"] == "Successfully created temporary file"
        # tempfile.mkstemp adds random characters to suffix, so returned name
        # will be different
        assert "filepath" in js and js["filepath"].startswith(os.path.join(form["dirpath"], form["prefix"]))
        assert os.path.exists(js["filepath"])
        assert os.path.isfile(js["filepath"])

    def test_mktemp_invalid(self):
        dirpath = self.non_existent_directory()
        form = {
            "dirpath": dirpath,
            "prefix": "",
            "suffix": "",
        }
        js = self.post_form("mktemp", form, 500)
        assert js["message"] == "Error creating temporary file"

    def test_mkdtemp_valid(self):
        form = {
            "dirpath": DIRPATH,
            "prefix": make_temp_name(),
            "suffix": "tmp",
        }
        js = self.post_form("mkdtemp", form)
        assert js["message"] == "Successfully created temporary directory"
        # tempfile.mkdtemp adds random characters to suffix, so returned name
        # will be different
        assert "dirpath" in js and js["dirpath"].startswith(os.path.join(form["dirpath"], form["prefix"]))
        assert os.path.exists(js["dirpath"])
        assert os.path.isdir(js["dirpath"])

    def test_mkdtemp_invalid(self):
        dirpath = self.non_existent_directory()
        assert not dirpath.exists()
        form = {
            "dirpath": dirpath,
            "prefix": "",
            "suffix": "",
        }
        js = self.post_form("mkdtemp", form, 500)
        assert js["message"] == "Error creating temporary directory"

    def test_extract(self):
        zfile = io.BytesIO()
        zf = zipfile.ZipFile(zfile, "w", zipfile.ZIP_DEFLATED, False)
        tempdir = make_temp_name()
        zf.writestr(os.path.join(tempdir, "test_file.txt"), "some test data")
        zf.close()
        zfile.seek(0)

        upload_file = {"zipfile": ("test_file.zip", zfile.read())}
        form = {"dirpath": DIRPATH}

        r = requests.post(f"{BASE_URL}/extract", files=upload_file, data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully extracted zip file"
        assert os.path.exists(os.path.join(DIRPATH, tempdir, "test_file.txt"))

    def test_extract_invalid(self):
        form = {"dirpath": DIRPATH}
        js = self.post_form("extract", form, 400)
        assert js["message"] == "No zip file has been provided"

        upload_file = {"zipfile": ("test_file.zip", "dummy data")}
        r = requests.post(f"{BASE_URL}/extract", files=upload_file)
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No dirpath has been provided"

    def test_execute(self):
        """Test executing the 'date' command."""
        if sys.platform == "win32":
            form = {"command": "cmd /c date /t"}
        else:
            form = {"command": "date"}
        js = self.post_form("execute", form)
        assert js["message"] == "Successfully executed command"
        assert "stdout" in js
        assert "stderr" in js
        current_year = datetime.date.today().isoformat()
        assert current_year[:4] in js["stdout"]

    def test_execute_error(self):
        """Expect an error on invalid command to execute."""
        js = self.post_form("execute", {}, 400)
        assert js["message"] == "No command has been provided"

        form = {"command": "ls"}
        js = self.post_form("execute", form, 500)
        assert js["message"] == "Not allowed to execute commands"

    def test_execute_py(self):
        """Test we can execute a simple python script."""
        # The output line endings are different between linux and Windows.
        file_contents = (
            "import sys",
            "print('hello world')",
            "print('goodbye world', file=sys.stderr)",
        )
        filepath = self.store_file(file_contents)

        form = {"filepath": filepath}
        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully executed command"
        assert "stdout" in js and "hello world" in js["stdout"]
        assert "stderr" in js and "goodbye world" in js["stderr"]

    def test_execute_py_error_no_file(self):
        """Ensure we get a 400 back when there's no file provided."""
        # The agent used to return 200 even in various failure scenarios.
        js = self.post_form("execpy", {}, expected_status=400)
        assert js["message"] == "No Python file has been provided"

    def test_execute_py_error_nonexistent_file(self):
        """Ensure we get a 400 back when a nonexistent filename is provided."""
        filepath = os.path.join(DIRPATH, make_temp_name() + ".py")
        form = {"filepath": filepath}
        assert not os.path.exists(filepath)
        js = self.post_form("execpy", form, expected_status=400)
        assert js["message"] == "Error executing python command."
        assert "stderr" in js and "No such file or directory" in js["stderr"]
        js = self.get_status()
        assert js["message"] == "Analysis status"
        assert js["status"] == "failed"

    def test_execute_py_error_non_zero_exit_code(self):
        """Ensure we get a 400 back when there's a non-zero exit code."""
        # Run a python script that exits non-zero.
        file_contents = (
            "import sys",
            "print('hello world')",
            "sys.exit(3)",
        )
        filepath = self.store_file(file_contents)
        form = {"filepath": filepath}
        js = self.post_form("execpy", form, expected_status=400)
        assert js["message"] == "Error executing python command."
        assert "hello world" in js["stdout"]
        js = self.get_status()
        assert js["message"] == "Analysis status"
        assert js["status"] == "failed"

    def test_async_running(self):
        """Test async execution shows as running after starting."""
        # upload test python file
        file_contents = (
            "import sys",
            "import time",
            "print('hello world')",
            "print('goodbye world', file=sys.stderr)",
            "time.sleep(1)",
            "sys.exit(0)",
        )
        filepath = self.store_file(file_contents)
        form = {"filepath": filepath, "async": 1}

        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully spawned command"
        assert "stdout" not in js
        assert "stderr" not in js
        assert "process_id" in js
        js = self.get_status()
        assert js["message"] == "Analysis status"
        assert js["status"] == "running"

    def test_async_complete(self):
        """Test async execution shows as complete after exiting."""
        # upload test python file
        file_contents = (
            "import random",
            "import sys",
            "import time",
            f"print('hello from {random.randint(1000, 9999)}', file=sys.stderr)",
            "sys.exit(0)",
        )
        filepath = self.store_file(file_contents)
        form = {"filepath": filepath, "async": 1}

        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully spawned command"
        # sleep a moment to let it finish
        time.sleep(2)
        js = self.get_status()
        assert js["message"] == "Analysis status"
        assert js["status"] == "complete"

    def test_async_failure(self):
        """Test that an unsuccessful script gets a status of 'failed'."""
        # upload test python file. It will sleep, then try to import a nonexistent module.
        file_contents = (
            "import sys",
            "import time",
            "time.sleep(1)",
            "import nonexistent",
            "print('hello world')",
            "print('goodbye world', file=sys.stderr)",
            "sys.exit(0)",
        )

        filepath = self.store_file(file_contents)
        form = {"filepath": filepath, "async": 1}

        js = self.post_form("execpy", form)
        assert js["message"] == "Successfully spawned command"
        assert "stdout" not in js
        assert "stderr" not in js
        assert "process_id" in js
        js = self.get_status()
        assert js["message"] == "Analysis status"
        assert js["status"] == "running"
        assert "process_id" in js
        time.sleep(2)

        # should still get a 200
        js = self.get_status(expected_status=200)
        assert js["message"] == "Analysis status"
        assert js["status"] == "failed"
        assert "process_id" not in js
