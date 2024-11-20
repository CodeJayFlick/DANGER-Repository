class InVmModelForDbgmodelBreakpointsTest:
    def get_break_pattern(self):
        return PathPattern("Sessions[0x0].Processes[].Debug.Breakpoints[]")

    def model_host(self) -> 'InVmDbgmodelModelHost':
        try:
            from . import InVmDbgmodelModelHost
            return InVmDbgmodelModelHost()
        except ImportError as e:
            raise TypeError(f"Failed to load {e}")
