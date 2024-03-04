import io
import multiprocessing
import os
import pathlib
import random
import sys
import tempfile
import uuid
import zipfile

import pytest
import requests

import agent

HOST = "127.0.0.1"
PORT = 8000
BASE_URL = f"http://{HOST}:{PORT}"
MAX_TRIES = 5

DIRPATH = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))


class TestAgent:
    """Test the agent API"""

    agent_process: multiprocessing.Process = None

    @classmethod
    def setup_class(cls):
        ev = multiprocessing.Event()
        TestAgent.agent_process = multiprocessing.Process(
            target=agent.app.run,
            kwargs={"host": HOST, "port": PORT, "event": ev},
        )
        TestAgent.agent_process.start()

        # wait for http server to start
        if not ev.wait(5.0):
            raise Exception("Failed to start agent HTTP server")

        # create temp directory for tests, as makes tidying up easier
        form = {"dirpath": DIRPATH, "mode": 0o777}
        r = requests.post(f"{BASE_URL}/mkdir", data=form)
        assert r.status_code == 200
        assert r.json()["message"] == "Successfully created directory"

    @classmethod
    def teardown_class(cls):
        # remove the temporary directory and files
        form = {"path": DIRPATH}
        r = requests.post(f"{BASE_URL}/remove", data=form)
        assert r.status_code == 200
        assert r.json()["message"] == "Successfully deleted directory"
        try:
            # shut down the agent service, which tests the kill endpoint
            r = requests.get(f"{BASE_URL}/kill")
            assert r.status_code == 200
            assert r.json()["message"] == "Quit the CAPE Agent"
        except requests.exceptions.ConnectionError:
            pass

        # clean up the multiprocessing stuff
        TestAgent.agent_process.join()
        TestAgent.agent_process.close()

    def make_temp_name(self):
        return str(uuid.uuid4())

    def non_existent_directory(self):
        root = pathlib.Path(tempfile.gettempdir()).root
        current_pid = os.getpid()
        return pathlib.Path(root, str(current_pid), str(random.randint(10000, 99999)))

    def test_root(self):
        r = requests.get(f"{BASE_URL}/")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "CAPE Agent!"
        assert "version" in js
        assert "features" in js

    def test_status_read(self):
        r = requests.get(f"{BASE_URL}/status")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Analysis status"
        assert "status" in js
        assert "description" in js

    def test_status_write_valid(self):
        form = {"status": 5, "description": "Test Status"}
        r = requests.post(f"{BASE_URL}/status", data=form)
        assert r.status_code == 200
        assert r.json()["message"] == "Analysis status updated"

        # do a get and check the results
        r = requests.get(f"{BASE_URL}/status")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Analysis status"
        assert js["status"] == "exception"
        assert js["description"] == "Test Status"

    def test_status_write_invalid(self):
        form = {"description": "Test Status"}
        r = requests.post(f"{BASE_URL}/status", data=form)
        assert r.status_code == 400
        assert r.json()["message"] == "No valid status has been provided"

    def test_logs(self):
        r = requests.get(f"{BASE_URL}/logs")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Agent logs"
        assert "stdout" in js
        assert "stderr" in js

    def test_system(self):
        r = requests.get(f"{BASE_URL}/system")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "System"
        assert "system" in js

    def test_environ(self):
        r = requests.get(f"{BASE_URL}/environ")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Environment variables"
        assert "environ" in js

    def test_path(self):
        r = requests.get(f"{BASE_URL}/path")
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Agent path"
        assert "filepath" in js

    def test_mkdir_valid(self):
        form = {
            "dirpath": os.path.join(DIRPATH, self.make_temp_name()),
            "mode": 0o777,
        }
        r = requests.post(f"{BASE_URL}/mkdir", data=form)
        assert r.status_code == 200
        assert r.json()["message"] == "Successfully created directory"

    def test_mkdir_invalid(self):
        form = {}
        r = requests.post(f"{BASE_URL}/mkdir", data=form)
        assert r.status_code == 400
        assert r.json()["message"] == "No dirpath has been provided"

        form = {"dirpath": "/", "mode": 0o777}
        r = requests.post(f"{BASE_URL}/mkdir", data=form)
        assert r.status_code == 500
        assert r.json()["message"] == "Error creating directory"

    def test_mktemp_valid(self):
        form = {
            "dirpath": DIRPATH,
            "prefix": self.make_temp_name(),
            "suffix": "tmp",
        }
        r = requests.post(f"{BASE_URL}/mktemp", data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully created temporary file"
        # tempfile.mkstemp adds random characters to suffix, so returned name
        # will be different
        assert "filepath" in js and js["filepath"].startswith(os.path.join(form["dirpath"], form["prefix"]))

    def test_mktemp_invalid(self):
        dirpath = self.non_existent_directory()
        assert not dirpath.exists()
        form = {
            "dirpath": dirpath,
            "prefix": "",
            "suffix": "",
        }
        r = requests.post(f"{BASE_URL}/mktemp", data=form)
        assert r.status_code == 500
        js = r.json()
        assert js["message"] == "Error creating temporary file"

    def test_mkdtemp_valid(self):
        form = {
            "dirpath": DIRPATH,
            "prefix": self.make_temp_name(),
            "suffix": "tmp",
        }
        r = requests.post(f"{BASE_URL}/mkdtemp", data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully created temporary directory"
        # tempfile.mkdtemp adds random characters to suffix, so returned name
        # will be different
        assert "dirpath" in js and js["dirpath"].startswith(os.path.join(form["dirpath"], form["prefix"]))

    def test_mkdtemp_invalid(self):
        dirpath = self.non_existent_directory()
        assert not dirpath.exists()
        form = {
            "dirpath": dirpath,
            "prefix": "",
            "suffix": "",
        }
        r = requests.post(f"{BASE_URL}/mkdtemp", data=form)
        assert r.status_code == 500
        js = r.json()
        assert js["message"] == "Error creating temporary directory"

    def test_store(self):
        sep = os.linesep
        upload_file = {"file": ("test_data.txt", f"test data{sep}test data{sep}")}
        path_to_create = os.path.join(DIRPATH, self.make_temp_name() + ".tmp")
        form = {"filepath": path_to_create}

        r = requests.post(f"{BASE_URL}/store", files=upload_file, data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully stored file"
        assert os.path.isfile(path_to_create)

    def test_store_invalid(self):
        # missing file
        form = {"filepath": os.path.join(DIRPATH, self.make_temp_name() + ".tmp")}
        r = requests.post(f"{BASE_URL}/store", data=form)
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No file has been provided"

        # missing filepath
        upload_file = {"file": ("test_data.txt", "test data\ntest data\n")}
        r = requests.post(f"{BASE_URL}/store", files=upload_file)
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No filepath has been provided"

        # destination file path is invalid
        upload_file = {"file": ("test_data.txt", "test data\ntest data\n")}
        form = {"filepath": os.path.join(DIRPATH, self.make_temp_name(), "tmp")}
        r = requests.post(f"{BASE_URL}/store", files=upload_file, data=form)
        assert r.status_code == 500
        js = r.json()
        assert js["message"].startswith("Error storing file:")

    def test_retrieve(self):
        upload_file = {"file": ("test_data.txt", "test data\ntest data\n")}
        form = {"filepath": os.path.join(DIRPATH, self.make_temp_name() + ".tmp")}

        r = requests.post(f"{BASE_URL}/store", files=upload_file, data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully stored file"

        r = requests.post(f"{BASE_URL}/retrieve", data=form)
        assert r.status_code == 200

    def test_retrieve_invalid(self):
        r = requests.post(f"{BASE_URL}/retrieve", data={})
        assert r.status_code == 400
        js = r.json()
        assert js["message"].startswith("No filepath has been provided")

        # request to retrieve non existent file
        form = {"filepath": os.path.join(DIRPATH, self.make_temp_name() + ".tmp")}
        r = requests.post(f"{BASE_URL}/retrieve", data=form)
        assert r.status_code == 404

    def test_extract(self):
        zfile = io.BytesIO()
        zf = zipfile.ZipFile(zfile, "w", zipfile.ZIP_DEFLATED, False)
        tempdir = self.make_temp_name()
        zf.writestr(os.path.join(tempdir, "test_file.txt"), "some test data")
        zf.close()
        zfile.seek(0)

        upload_file = {"zipfile": ("test_file.zip", zfile.read())}
        form = {"dirpath": DIRPATH}

        r = requests.post(f"{BASE_URL}/extract", files=upload_file, data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully extracted zip file"

        # todo should I check the filesytem for the file?

    def test_extract_invalid(self):
        form = {"dirpath": DIRPATH}
        r = requests.post(f"{BASE_URL}/extract", data=form)
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No zip file has been provided"

        upload_file = {"zipfile": ("test_file.zip", "dummy data")}
        r = requests.post(f"{BASE_URL}/extract", files=upload_file)
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No dirpath has been provided"

    def test_remove(self):
        tempdir = os.path.join(DIRPATH, self.make_temp_name())
        tempfile = os.path.join(tempdir, self.make_temp_name())

        # create temp directory
        form = {
            "dirpath": tempdir,
            "mode": 0o777,
        }
        r = requests.post(f"{BASE_URL}/mkdir", data=form)

        # create file in temp directory
        upload_file = {"file": ("test_data.txt", "test data\ntest data\n")}
        form = {"filepath": tempfile}
        r = requests.post(f"{BASE_URL}/store", files=upload_file, data=form)

        # delete temp file
        form = {"path": tempfile}
        r = requests.post(f"{BASE_URL}/remove", data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully deleted file"

        # delete temp directory
        form = {"path": tempdir}
        r = requests.post(f"{BASE_URL}/remove", data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully deleted directory"

    def test_remove_invalid(self):
        tempdir = os.path.join(DIRPATH, self.make_temp_name())

        # missing parameter
        form = {}
        r = requests.post(f"{BASE_URL}/remove", data=form)
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No path has been provided"

        # path doesn't exist
        form = {"path": tempdir}
        r = requests.post(f"{BASE_URL}/remove", data=form)
        assert r.status_code == 404
        js = r.json()
        assert js["message"] == "Path provided does not exist"

        # error removing file or dir (permission)
        form = {"path": tempfile.gettempdir()}
        r = requests.post(f"{BASE_URL}/remove", data=form)
        assert r.status_code == 500
        js = r.json()
        assert js["message"] == "Error removing file or directory"

    @staticmethod
    def command_execute_should_succeed(command):
        """Execute a non-python command that should succeed."""
        form = {"command": command}
        r = requests.post(f"{BASE_URL}/execute", data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully executed command"
        assert "stdout" in js
        assert "stderr" in js

    @pytest.mark.xfail(sys.platform == "win32", reason="This is a linux-only test.")
    def test_execute_linux(self):
        self.command_execute_should_succeed("date")

    @pytest.mark.xfail(sys.platform == "linux", reason="This is a windows-only test.")
    def test_execute_windows(self):
        self.command_execute_should_succeed("cmd /c date /t")

    def test_execute_error(self):
        form = {"command": "ls"}
        r = requests.post(f"{BASE_URL}/execute", data=form)
        assert r.status_code == 500
        js = r.json()
        assert js["message"] == "Not allowed to execute commands"

        r = requests.post(f"{BASE_URL}/execute", data={})
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No command has been provided"

    def test_execute_py(self):
        """Upload and execute a python file."""
        sample_string = "hello world"
        upload_file = {"file": ("test.py", f"print('{sample_string}')")}
        filepath = os.path.join(DIRPATH, self.make_temp_name() + ".py")
        form = {"filepath": filepath}
        r = requests.post(f"{BASE_URL}/store", files=upload_file, data=form)
        assert r.status_code == 200
        assert os.path.isfile(filepath)

        r = requests.post(f"{BASE_URL}/execpy", data=form)
        assert r.status_code == 200
        js = r.json()
        assert js["message"] == "Successfully executed command"
        assert "stdout" in js and js["stdout"].strip() == sample_string
        assert "stderr" in js and js["stderr"] == ""

    def test_execute_py_error(self):
        r = requests.post(f"{BASE_URL}/execpy", data={})
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "No Python file has been provided"

        # Attempt to run non-existent file. Will return 400,
        # and stderr will have a message.
        filepath = os.path.join(DIRPATH, self.make_temp_name() + ".py")
        form = {"filepath": filepath}
        r = requests.post(f"{BASE_URL}/execpy", data=form)
        assert r.status_code == 400
        js = r.json()
        assert js["message"] == "Error executing python command."
        assert "stderr" in js and "No such file or directory" in js["stderr"]

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
