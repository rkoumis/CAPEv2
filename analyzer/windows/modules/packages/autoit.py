from lib.common.abstracts import Package


class AutoIT(Package):
    """AutoIT analysis package."""

    summary = """Execute the sample with autoit3."""
    description = """Use bin\\autoit3.exe to execute the sample,
    Use the 'arguments' option to provide arguments to the sample."""
    option_names = ("arguments",)

    def start(self, path):
        arguments = self.options.get("arguments", "")
        return self.execute("bin\\autoit3.exe", f"{path} {arguments}", path)
