class VTMatchDestinationAddressToProgramLocationTableRowMapper:
    def create_mapped_table_column(self, destination_column):
        if isinstance(destination_column, ProgramLocationTableColumn):
            return VTMatchDestinationWrappedMappedProgramLocationTableColumn(self, destination_column)
        else:
            return VTMatchDestinationWrappedMappedTableColumn(self, destination_column)

    def map(self, row_object, program, service_provider):
        association = row_object.get_association()
        destination_address = association.get_destination_address()
        return ProgramLocation(program, destination_address)


class VTMatchDestinationWrappedMappedProgramLocationTableColumn:
    def __init__(self, mapper, table_column):
        super().__init__(mapper, table_column)

    def get_value(self, row_object, settings, data, service_provider):
        destination_program = row_object.get_match_set().get_session().get_destination_program()
        return super().get_value(row_object, settings, destination_program, service_provider)


class VTMatchDestinationWrappedMappedTableColumn:
    def __init__(self, mapper, table_column):
        super().__init__(mapper, table_column)

    def get_value(self, row_object, settings, data, service_provider):
        destination_program = row_object.get_match_set().get_session().get_destination_program()
        return super().get_value(row_object, settings, destination_program, service_provider)


class ProgramLocation:
    def __init__(self, program, address):
        self.program = program
        self.address = address


# Usage example:

mapper = VTMatchDestinationAddressToProgramLocationTableRowMapper()

destination_column1 = ProgramLocationTableColumn()
destination_column2 = DynamicTableColumn()

wrapped_mapped_program_location_table_column1 = mapper.create_mapped_table_column(destination_column1)
wrapped_mapped_program_location_table_column2 = mapper.create_mapped_table_column(destination_column2)

program_location1 = mapper.map(row_object, program, service_provider)
program_location2 = mapper.map(row_object, program, service_provider)
