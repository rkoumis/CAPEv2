from lib.common.abstracts import Package


class OllyDbg(Package):
    """OllyDbg analysis package."""

    summary = "Open the sample with OllyDbg"
    description = """Use 'bin\\OllyDbg\OLLYDBG.EXE <sample> [arguments]' to launch the sample.
    The 'arguments' option can be used to pass additional arguments."""
    option_names = ("arguments",)

    def start(self, path):
        arguments = self.options.get("arguments", "")
        return self.execute("bin\\OllyDbg\\OLLYDBG.EXE", f"{path} {arguments}", path)
