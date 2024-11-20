Here is the translation of the given Java code into Python:

```Python
class SharedReturnAnalyzer:
    NAME = "Shared Return Calls"
    DESCRIPTION = ("Converts branches to calls, followed by an immediate return,"
                   "when the destination is a function."
                  "Since this analysis is triggered by the creation of the destination function,"
                  "the one-shot analysis action can be used if functions were created while this"
                  "analyzer was disabled or not present.")

    OPTION_NAME_ASSUME_CONTIGUOUS_FUNCTIONS = "Assume Contiguous Functions Only"
    OPTION_DESCRIPTION_ASSUME_CONTIGUOUS_FUNCTIONS = ("Signals to assume all function bodies are contiguous "
                                                         "and all jumps across other functions should be treated as a call-return.")
    
    OPTION_NAME_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS = "Allow Conditional Jumps"
    OPTION_DESCRIPTION_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS = ("Signals to allow conditional jumps to be consider for "
                                                                    "shared return jumps to other functions.")

    DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED = False
    DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED = False

    def __init__(self):
        self.assumeContiguousFunctions = self.DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED
        self.considerConditionalBranches = self.DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED

    def added(self, program: 'Program', set: 'AddressSetView', monitor: 'TaskMonitor', log: 'MessageLog') -> bool:
        cmd = SharedReturnAnalysisCmd(set, self.assumeContiguousFunctions,
                                       self.considerConditionalBranches)
        cmd.applyTo(program)

        return True

    def getDefaultEnablement(self, program: 'Program') -> bool:
        language = program.getLanguage()

        shared_return_enabled = language.getPropertyAsBoolean(
            GhidraLanguagePropertyKeys.ENABLE_SHARED_RETURN_ANALYSIS, True
        )

        return shared_return_enabled

    def registerOptions(self, options: dict, program: 'Program'):
        help_location = "AutoAnalysisPlugin", "Auto_Analysis_Option_Instructions"

        options[OPTION_NAME_ASSUME_CONTIGUOUS_FUNCTIONS] = self.DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED, help_location, OPTION_DESCRIPTION_ASSUME_CONTIGUOUS_FUNCTIONS
        options[OPTION_NAME_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS] = self.DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED, help_location, OPTION_DESCRIPTION_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS

    def optionsChanged(self, options: dict, program: 'Program'):
        self.assumeContiguousFunctions = options.get(OPTION_NAME_ASSUME_CONTIGUOUS_FUNCTIONS,
                                                      self.DEFAULT_ASSUME_CONTIGUOUS_FUNCTIONS_ENABLED)
        self.considerConditionalBranches = options.get(OPTION_NAME_CONSIDER_CONDITIONAL_BRANCHES_FUNCTIONS,
                                                       self.DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED)

class Program:
    def getLanguage(self):
        pass

class AddressSetView:
    pass

class TaskMonitor:
    pass

class MessageLog:
    pass
```

Please note that Python does not have direct equivalent of Java's static methods, so I've used class variables instead. Also, some classes like `Program`, `AddressSetView`, `TaskMonitor` and `MessageLog` are not defined in the given code snippet, but they should be present to make this code work correctly.