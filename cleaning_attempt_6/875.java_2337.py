class InVmModelForDbgengProcessActivationTest:
    def __init__(self):
        pass

    def get_process_pattern(self):
        return "Sessions[0].Processes[]"

    def model_host(self) -> 'InVmDbgengModelHost':
        from . import InVmDbgengModelHost
        return InVmDbgengModelHost()

    def get_expected_session_path(self):
        return ["Sessions[0]"]

    def id_from_capture(self, line: str) -> str:
        parts = line.split()
        if len(parts) > 1:
            return parts[1]
        else:
            return ""
