class SymbolNameProgramCorrelatorFactory:
    DESC = "Compares symbols by iterating over all defined function" + \
           "and data symbols meeting the minimum size requirement in the source program and looking for" + \
           "identical symbol matches in the destination program. It ignores default symbols such as those" + \
           "starting with FUN_, DAT_, s_, and u_. It strips off the ending address that is sometimes included" + \
           "on symbols. It reports back any that have ONLY ONE identical match."
    EXACT_SYMBOL_MATCH = "Exact Symbol Name Match"

    MIN_SYMBOL_NAME_LENGTH_DEFAULT = 3
    MIN_SYMBOL_NAME_LENGTH = f"Minimum Symbol Name Length ({MIN_SYMBOL_NAME_LENGTH_DEFAULT})"

    INCLUDE_EXTERNAL_SYMBOLS_DEFAULT = True
    INCLUDE_EXTERNAL_SYMBOLS = f"Include External Function Symbols ({INCLUDE_EXTERNAL_SYMBOLS_DEFAULT})"

    def get_priority(self):
        return 40

    def create_correlator(self, service_provider: object, source_program: str, 
                          source_address_set: str, destination_program: str, 
                          destination_address_set: str, options: dict) -> object:
        return SymbolNameProgramCorrelator(service_provider, source_program, 
                                            source_address_set, destination_program, 
                                            destination_address_set, options, self.EXACT_SYMBOL_MATCH, True)

    def get_name(self):
        return self.EXACT_SYMBOL_MATCH

    def create_default_options(self) -> dict:
        default_options = {self.EXACT_SYMBOL_MATCH: {}}
        default_options[self.EXACT_SYMBOL_MATCH][self.MIN_SYMBOL_NAME_LENGTH] = self.MIN_SYMBOL_NAME_LENGTH_DEFAULT
        default_options[self.EXACT_SYMBOL_MATCH][self.INCLUDE_EXTERNAL_SYMBOLS] = self.INCLUDE_EXTERNAL_SYMBOLS_DEFAULT
        return default_options

    def get_description(self):
        return self.DESC


class SymbolNameProgramCorrelator:
    def __init__(self, service_provider: object, source_program: str, 
                 source_address_set: str, destination_program: str, 
                 destination_address_set: str, options: dict, name: str, exact_match: bool) -> None:
        self.service_provider = service_provider
        self.source_program = source_program
        self.source_address_set = source_address_set
        self.destination_program = destination_program
        self.destination_address_set = destination_address_set
        self.options = options
        self.name = name
        self.exact_match = exact_match


# Example usage:
factory = SymbolNameProgramCorrelatorFactory()
correlator = factory.create_correlator(None, "source_program", 
                                        "source_address_set", "destination_program", 
                                        "destination_address_set", {})
print(factory.get_name())  # Output: Exact Symbol Name Match
