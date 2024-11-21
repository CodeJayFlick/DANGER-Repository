class SkeletonAnalyzer:
    def __init__(self):
        # TODO: Name the analyzer and give it a description.
        self.name = "My Analyzer"
        self.description = "Analyzer description goes here"

    def get_default_enablement(self, program):
        # TODO: Return true if analyzer should be enabled by default
        return False

    def can_analyze(self, program):
        # TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
        # if it can.
        return False

    def register_options(self, options, program):
        # TODO: If this analyzer has custom options, register them here
        option_name = "Option name goes here"
        default_value = False
        description = "Option description goes here"

        options.register_option(option_name, default_value, None, description)

    def added(self, program, set, monitor, log):
        # TODO: Perform analysis when things get added to the 'program'.  Return true if the
        # analysis succeeded.
        return False

# Usage:
analyzer = SkeletonAnalyzer()
