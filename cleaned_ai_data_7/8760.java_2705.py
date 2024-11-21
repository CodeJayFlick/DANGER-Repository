class ExactMatchInstructionsProgramCorrelatorFactory:
    DESCRIPTION = "Compares code by hashing instructions, looking for identical functions. It reports back any that have ONLY ONE identical match."
    
    EXACT_MATCH = "Exact Function Instructions Match"
    FUNCTION_MINIMUM_SIZE_DEFAULT = 10
    
    def get_priority(self):
        return 30

    def create_correlator(self, service_provider: object, source_program: object, 
                          source_address_set: object, destination_program: object, 
                          destination_address_set: object, options: dict) -> object:
        from ghidra.feature.vt.api.correlator.program import FunctionMatchProgramCorrelator
        return FunctionMatchProgramCorrelator(service_provider, source_program, 
                                              source_address_set, destination_program, 
                                              destination_address_set, options, self.EXACT_MATCH, True, 
                                              ExactInstructionsFunctionHasher.INSTANCE)

    def get_name(self):
        return self.EXACT_MATCH

    def create_default_options(self) -> dict:
        from ghidra.feature.vt.api.util import VTOptions
        default_options = VTOptions(self.EXACT_MATCH)
        default_options.set_int('FUNCTION_MINIMUM_SIZE', self.FUNCTION_MINIMUM_SIZE_DEFAULT)
        return default_options

    def get_description(self):
        return self.DESCRIPTION


# Example usage:
factory = ExactMatchInstructionsProgramCorrelatorFactory()
print(factory.get_name())  # prints: "Exact Function Instructions Match"
