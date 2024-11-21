class FunctionStartPostAnalyzer:
    FUNCTION_START_POST_SEARCH = "Function Start Post Search"

    def __init__(self):
        super().__init__("After Code", AnalyzerType.INSTRUCTION_ANALYZER)
        self.set_supports_one_time_analysis(False)
        self.set_priority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before())

    def can_analyze(self, program: "Program") -> bool:
        if not super().can_analyze(program):
            return False
        local_root = self.initialize(program)
        if local_root is None:
            return False
        if self.has_code_constraints or self.has_data_constraints:
            # cache the localRoot
            self.root_state = local_root
            return True
        return False

class Program:  # assuming this class exists in Python, otherwise you'll need to define it
    pass

AnalyzerType = enum("INSTRUCTION_ANALYZER")
AnalysisPriority = enum("DATA_TYPE_PROPOGATION")

def set_supports_one_time_analysis(self, value):
    pass

def set_priority(self, priority):
    pass

def has_code_constraints(self) -> bool:
    return False

def has_data_constraints(self) -> bool:
    return False
