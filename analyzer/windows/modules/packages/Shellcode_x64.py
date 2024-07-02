# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package


class Shellcode_x64(Package):
    """64-bit Shellcode analysis package."""

    summary = "Execute 64-bit Shellcode using loader_x64.exe."
    description = """Use bin\\loader_x64.exe shellcode [offset] <sample> to execute 64-bit Shellcode."
    Turn off the 'procdump' option."""
    option_names = ("offset",)

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options["procdump"] = "0"

    def start(self, path):
        offset = self.options.get("offset")
        loaderpath = "bin\\loader_x64.exe"
        args = f"shellcode {path}"
        if offset:
            args += f" {offset}"
        # we need to move out of the analyzer directory
        # due to a check in monitor dll
        basepath = os.path.dirname(path)
        newpath = os.path.join(basepath, os.path.basename(loaderpath))
        shutil.copy(loaderpath, newpath)

        return self.execute(newpath, args, newpath)
