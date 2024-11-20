class ExactMatchBytesProgramCorrelatorFactory:
    DESCRIPTION = "Compares code by hashing bytes, looking for identical functions. It reports back any that have ONLY ONE identical match."
    EXACT_MATCH = "Exact Function Bytes Match"
    FUNCTION_MINIMUM_SIZE_DEFAULT = 10

    def get_priority(self):
        return 20

    def create_correlator(self, service_provider: object, source_program: object,
                          source_address_set: object, destination_program: object,
                          destination_address_set: object, options: dict) -> object:
        from ghidra.program.model.listing import Program
        from ghidra.app.plugin.match import ExactBytesFunctionHasher

        return FunctionMatchProgramCorrelator(service_provider, source_program, 
                                              source_address_set, destination_program, 
                                              destination_address_set, options, EXACT_MATCH, True,
                                              ExactBytesFunctionHasher.INSTANCE)

    def get_name(self):
        return self.EXACT_MATCH

    def create_default_options(self) -> dict:
        from ghidra.feature.vt.api.util import VTOptions
        options = VTOptions(self.EXACT_MATCH)
        options['function_minimum_size'] = self.FUNCTION_MINIMUM_SIZE_DEFAULT
        return options

    def get_description(self):
        return self.DESCRIPTION


class FunctionMatchProgramCorrelator:
    pass  # This class is not implemented in the original code, so I left it as a placeholder.
