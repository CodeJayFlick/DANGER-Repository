import logging

class MicrosoftDemanglerAnalyzer:
    NAME = "Demangler Microsoft"
    DESCRIPTION = (
        "After a function is created, this analyzer will attempt "
        "to demangle the name and apply datatypes to parameters."
    )
    OPTION_NAME_APPLY_SIGNATURE = "Apply Function Signatures"
    OPTION_DESCRIPTION_APPLY_SIGNATURE = (
        "Apply any recovered function signature, in addition "
        "to the function name"
    )

    def __init__(self):
        self.apply_function_signature = True
        self.demangler = MicrosoftDemangler()

    @property
    def apply_function_signature(self):
        return self._apply_function_signature

    @apply_function_signature.setter
    def apply_function_signature(self, value):
        self._apply_function_signature = value

    def can_analyze(self, program: "Program") -> bool:
        return self.demangler.can_demangle(program)

    def register_options(self, options, program):
        options.register_option(
            OPTION_NAME_APPLY_SIGNATURE,
            self.apply_function_signature,
            None,
            OPTION_DESCRIPTION_APPLY_SIGNATURE
        )

    def options_changed(self, options, program):
        self.apply_function_signature = (
            options.get_boolean(OPTION_NAME_APLY_SIGNATURE)
            if hasattr(options, "get_boolean")
            else True  # default to true for Python < 3.8
        )

    def demangle(self, mangled: str, options: dict, log) -> dict:
        try:
            return self.demangler.demangle(mangled, options)
        except Exception as e:
            logging.error(f"Error demangling {mangled}: {e}")
            raise

class Program:
    pass  # placeholder for the Python equivalent of a Java program object
