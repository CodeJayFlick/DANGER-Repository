Here is the translation of the given Java code into equivalent Python:

```Python
class InVmModelForLldbFrameActivationTest:
    def __init__(self):
        pass

    def get_stack_pattern(self):
        return "Sessions[].Processes[].Threads[].Stack[]"

    def get_expected_default_active_path(self):
        return ["Sessions[].Processes[].Threads[].Stack[0]"]

    def id_from_capture(self, line):
        # Syntax  "frame #N:..."
        split = line.split(":")
        frame_id = int(split[0].split("#")[1])
        return str(frame_id)

    def model_host(self) -> 'ModelHost':
        from . import InVmLldbModelHost
        return InVmLlb