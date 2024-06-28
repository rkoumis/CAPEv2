# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class Regsvr(Package):
    """DLL analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "regsvr32.exe"),
    ]
    summary = "Open the file with regsvr32.exe"
    description = """Use 'regsvr32.exe to open a .dll file.
    If the 'arguments' option is set, the contents will be used as arguments to regsvr32.exe.
    The .dll extension will be added automatically."""
    option_names = ("arguments",)

    def start(self, path):
        regsvr32 = self.get_path("regsvr32.exe")
        arguments = self.options.get("arguments")

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        path = check_file_extension(path, ".dll")

        args = ""
        if arguments:
            args += f"{arguments} "
        args += path

        return self.execute(regsvr32, args, path)
