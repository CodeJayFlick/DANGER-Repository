import re

class InVmModelForDbgengThreadActivationTest:
    def get_thread_pattern(self):
        return "Sessions[0].Processes[].Threads[]"

    def model_host(self) -> 'InVmDbgengModelHost':
        from . import InVmDbgengModelHost
        return InVmDbgengModelHost()

    def get_expected_session_path(self) -> list:
        return ["Sessions[0]"]

    def id_from_capture(self, line: str):
        parts = re.split(r'\s+', line)
        return parts[1]
