Here is the translation of the given Java code into Python:

```Python
class StackVariableAnalyzer:
    NAME = "Stack"
    DESCRIPTION = "Creates stack variables for a function."

    def __init__(self):
        self.do_new_stack_analysis = True
        self.do_local_analysis = True
        self.do_parameter_analysis = True

    @property
    def name(self):
        return self.NAME

    @property
    def description(self):
        return self.DESCRIPTION

    def added(self, program: 'Program', set: 'AddressSetView', monitor: 'TaskMonitor', log: 'MessageLog') -> bool:
        if self.do_new_stack_analysis:
            cmd = NewFunctionStackAnalysisCmd(set, do_parameter_analysis=self.do_parameter_analysis, 
                                               do_local_analysis=self.do_local_analysis, is_reduced=False)
        else:
            cmd = FunctionStackAnalysisCmd(set, do_parameter_analysis=self.do_parameter_analysis, 
                                           do_local_analysis=self.do_local_analysis, is_reduced=False)

        cmd.apply_to(program=program, monitor=monitor)
        return True

    def use_old_stack_analysis_by_default(self, program: 'Program') -> bool:
        language = program.get_language()
        if language.get_processor().name == "x86":
            if language.get_language_description().size == 16:
                # Prefer using old stack analysis for x86 16-bit with segmented addresses
                return True

    def register_options(self, options: 'Options', program: 'Program') -> None:
        options.register_option("USE_NEW_FUNCTION_STACK_ANALYSIS", 
                                 not self.use_old_stack_analysis_by_default(program), 
                                 "Use General Stack Reference Propogator (This works best on most processors)")

        options.register_option("CREATE_LOCAL_VARIABLES", self.do_local_analysis, 
                                "Create Function Local stack variables and references")

        options.register_option("CREATE_PARAM_VARIABLES", self.do_parameter_analysis, 
                                "Create Function Parameter stack variables and references")

    def options_changed(self, options: 'Options', program: 'Program') -> None:
        self.do_new_stack_analysis = not self.use_old_stack_analysis_by_default(program)
        self.do_local_analysis = options.get_boolean("CREATE_LOCAL_VARIABLES", self.do_local_analysis)
        self.do_parameter_analysis = options.get_boolean("CREATE_PARAM_VARIABLES", self.do_parameter_analysis)

class Program: pass
class AddressSetView: pass
class TaskMonitor: pass
class MessageLog: pass

# Usage:
analyzer = StackVariableAnalyzer()
program = Program()  # Replace with your actual program object.
set = AddressSetView()  # Replace with your actual set of addresses.
monitor = TaskMonitor()  # Replace with your actual task monitor.
log = MessageLog()  # Replace with your actual message log.

# Now you can call the methods:
analyzer.added(program, set, monitor, log)
```

Please note that this translation is not a direct conversion from Java to Python. The original code seems to be part of a larger system (Ghidra) and uses specific classes and interfaces which are not available in standard Python. Therefore, I had to replace these with placeholder types (`Program`, `AddressSetView`, etc.).