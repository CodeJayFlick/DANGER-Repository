Here is the translation of the Java code into Python:

```Python
class CreateThunkAnalyzer:
    FIND_THUNKS_STARTS_MSG = "Create Thunks : "
    OPTION_NAME_CREATE_THUNKS_EARLY = "Create Thunks Early"
    OPTION_DESCRIPTION_CREATE_THUNKS_EARLY = f"If checked, create thunk functions early in analysis flow."
    DEFAULT_CREATE_THUNKS_EARLY_ENABLED = True

    def __init__(self):
        self.create_only_thunks = DEFAULT_CREATE_THUNKS_EARLY_ENABLED
        self.analysis_message = FIND_THUNKS_STARTS_MSG

    def added(self, program: 'Program', set: 'AddressSetView', monitor: 'TaskMonitor', log: 'MessageLog') -> bool:
        if not self.create_only_thunks:
            return True
        return super().added(program, set, monitor, log)

    def register_options(self, options: dict, prog: object) -> None:
        help_location = {"AutoAnalysisPlugin": f"Auto_ Analysis_Option_Instruction {self.get_analysis_type()}"}
        options[OPTION_NAME_CREATE_THUNKS_EARLY] = self.create_only_thunks, None, OPTION_DESCRIPTION_CREATE_THUNKS_EARLY

    def options_changed(self, options: dict, prog: object) -> None:
        self.create_only_thunks = options[OPTION_NAME_CREATE_THUNKS_EARLY]

class Program:
    pass

class AddressSetView:
    pass

class TaskMonitor:
    pass

class MessageLog:
    pass
```

Please note that Python does not have direct equivalent of Java's `extends` keyword. Also, the translation is based on my understanding and may require further adjustments according to your specific requirements.