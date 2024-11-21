class X86FunctionPurgeAnalyzer:
    NAME = "X86 Function Callee Purge"
    DESCRIPTION = f"Figures out the function Purge value for Callee cleaned up function call parameters (stdcall) on X86 platforms."

    def __init__(self):
        self.priority = AnalysisPriority.FUNCTION_ANALYSIS
        self.default_enablement = True

    def added(self, program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog):
        cmd = FunctionPurgeAnalysisCmd(set)
        cmd.apply_to(program=program, monitor=monitor)

        return True


class AnalysisPriority:
    FUNCTION_ANALYSIS = 1
