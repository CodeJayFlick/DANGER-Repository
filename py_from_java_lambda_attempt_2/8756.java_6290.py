Here is a translation of the provided Java code into equivalent Python:

```Python
class DuplicateFunctionMatchProgramCorrelatorFactory:
    DESCRIPTION = "Compares code by hashing instructions (masking off operands), looking for identical functions.  It reports back any that have MORE THAN ONE identical match."
    DUPLICATE_MATCH = "Duplicate Function Instructions Match"
    MAX_MATCHES = 10

    def get_priority(self):
        return 80

    def create_correlator(self, service_provider: object, source_program: object,
                          source_address_set: object, destination_program: object,
                          destination_address_set: object, options: dict) -> object:
        from ghidra.feature.vt.api.correlator.program import FunctionMatchProgramCorrelator
        return FunctionMatchProgramCorrelator(service_provider, source_program, source_address_set,
                                              destination_program, destination_address_set, options,
                                              DUPLICATE_MATCH, False, ExactInstructionsFunctionHasher.INSTANCE)

    def get_name(self):
        return self.DUPLICATE_MATCH

    def create_default_options(self) -> dict:
        from ghidra.feature.vt.api.correlator.program import VTOptions
        options = VTOptions(DUPLICATE_MATCH)
        options['int'] = {
            'function_minimum_size': ExactMatchInstructionsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE_DEFAULT,
        }
        return options

    def get_description(self):
        return self.DESCRIPTION


# Usage:
factory = DuplicateFunctionMatchProgramCorrelatorFactory()
print(factory.get_priority())
correlator = factory.create_correlator(None, None, None, None, None, {})
print(correlator)
options = factory.create_default_options()
print(options)
```

Please note that this translation is not perfect and may require adjustments based on the actual usage of these classes in your Python program.