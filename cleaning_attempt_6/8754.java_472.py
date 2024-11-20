class DataReferenceProgramCorrelatorFactory:
    def __init__(self):
        super().__init__()
        self.name = "Data Reference Match"
        self.correlator_description = (
            "Matches functions by the accepted data matches they have in common."
        )

    def create_correlator(self, service_provider: object,
                          source_program: object,
                          source_address_set: object,
                          destination_program: object,
                          destination_address_set: object,
                          options: object) -> object:
        return DataReferenceProgramCorrelator(
            service_provider=service_provider,
            source_program=source_program,
            source_address_set=source_address_set,
            destination_program=destination_program,
            destination_address_set=destination_address_set,
            correlator_name=self.name,
            options=options
        )


class VTAbstractReferenceProgramCorrelatorFactory:
    pass


class DataReferenceProgramCorrelator:
    def __init__(self, service_provider: object,
                          source_program: object,
                          source_address_set: object,
                          destination_program: object,
                          destination_address_set: object,
                          correlator_name: str,
                          options: object) -> None:
        self.service_provider = service_provider
        self.source_program = source_program
        self.source_address_set = source_address_set
        self.destination_program = destination_program
        self.destination_address_set = destination_address_set
        self.correlator_name = correlator_name
