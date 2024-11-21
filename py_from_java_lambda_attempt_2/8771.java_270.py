Here is the equivalent Python code:

```Python
class SimilarSymbolNameProgramCorrelatorFactory:
    NAME = "Similar Symbol Name Match"
    MEMORY_MODEL_DEFAULT = "LARGE"
    MIN_NAME_LENGTH_DEFAULT = 6

    def get_priority(self):
        return 9001

    def create_correlator(self, service_provider, source_program, source_address_set,
                          destination_program, destination_address_set, options):
        from . import SimilarSymbolNameProgramCorrelator
        return SimilarSymbolNameProgramCorrelator(
            service_provider, source_program, source_address_set,
            destination_program, destination_address_set, options)

    def get_name(self):
        return self.NAME

    def create_default_options(self):
        from vartools.vt import VTOptions
        options = VTOptions(self.NAME)
        options.set_enum("Memory model", self.MEMORY_MODEL_DEFAULT)
        options.set_int("Minimum name length", self.MIN_NAME_LENGTH_DEFAULT)
        return options

    def get_description(self):
        return ("Compares symbols by iterating over all "
                "defined function and data symbols meeting the minimum size requirement in "
                "the source program and looking for similar symbol matches in the destination "
                "program.  It reports back any that match closely.")
```

Note: This Python code is not a direct translation of the Java code, but rather an equivalent implementation using Python classes and methods. The `from . import SimilarSymbolNameProgramCorrelator` line assumes that you have defined another class called `SimilarSymbolNameProgramCorrelator` in the same package or module as this one.