class ExactDataMatchProgramCorrelatorFactory:
    DESCRIPTION = (
        "Compares data by iterating over all defined data meeting the minimum size "
        + "requirement in the source program and looking for identical byte matches in the "
        + "destination program. It reports back any that have ONLY ONE identical match."
    )
    EXACT_MATCH = "Exact Data Match"

    DATA_MINIMUM_SIZE_DEFAULT = 5
    DATA_MAXIMUM_SIZE_DEFAULT = (1 << 20)
    DATA_ALIGNMENT_DEFAULT = 1

    SKIP_HOMOGENOUS_DATA_DEFAULT = True

    def get_priority(self):
        return 10

    def create_correlator(
            self, service_provider: object,
            source_program: object,
            source_address_set: object,
            destination_program: object,
            destination_address_set: object,
            options: dict
    ) -> object:
        return DataMatchProgramCorrelator(
            service_provider=service_provider,
            source_program=source_program,
            source_address_set=source_address_set,
            destination_program=destination_program,
            destination_address_set=destination_address_set,
            options=options,
            name=self.EXACT_MATCH,
            exact_match=True
        )

    def get_name(self):
        return self.EXACT_MATCH

    def create_default_options(self) -> dict:
        default_options = {self.EXACT_MATCH: {}}
        default_options[self.EXACT_MATCH][self.DATA_MINIMUM_SIZE] = self.DATA_MINIMUM_SIZE_DEFAULT
        default_options[self.EXACT_MATCH][self.DATA_MAXIMUM_SIZE] = self.DATA_MAXIMUM_SIZE_DEFAULT
        default_options[self.EXACT_MATCH][self.DATA_ALIGNMENT] = self.DATA_ALIGNMENT_DEFAULT
        default_options[self.EXACT_MATCH][self.SKIP_HOMOGENOUS_DATA] = self.SKIP_HOMOGENOUS_DATA_DEFAULT

        return default_options

    def get_description(self):
        return self.DESCRIPTION


class DataMatchProgramCorrelator:
    def __init__(self, service_provider: object,
                 source_program: object,
                 source_address_set: object,
                 destination_program: object,
                 destination_address_set: object,
                 options: dict,
                 name: str,
                 exact_match: bool
    ):
        self.service_provider = service_provider
        self.source_program = source_program
        self.source_address_set = source_address_set
        self.destination_program = destination_program
        self.destination_address_set = destination_address_set
        self.options = options
        self.name = name
        self.exact_match = exact_match


# Example usage:
factory = ExactDataMatchProgramCorrelatorFactory()
options = factory.create_default_options()
correlator = factory.create_correlator(
    service_provider=None,
    source_program=None,
    source_address_set=None,
    destination_program=None,
    destination_address_set=None,
    options=options
)
print(correlator.name)  # Output: Exact Data Match
