class VTMatchSourceAddressToProgramLocationTableRowMapper:
    def create_mapped_table_column(self, destination_column):
        if isinstance(destination_column, ProgramLocationTableColumn):
            return VTMatchSourceWrappedMappedProgramLocationTableColumn(self, destination_column)
        else:
            return VTMatchSourceWrappedMappedTableColumn(self, destination_column)

    def map(self, row_object, program, service_provider):
        association = row_object.get_association()
        source_address = association.get_source_address()
        return ProgramLocation(program, source_address)


class VTMatchSourceWrappedMappedProgramLocationTableColumn:
    def __init__(self, mapper, table_column):
        super().__init__(mapper, table_column)

    def get_column_display_name(self, settings):
        return "Source " + super().get_column_display_name(settings)

    def get_column_description(self):
        return super().get_column_name() + " (for a match's source address)"

    def get_column_name(self):
        return "Source " + super().get_column_name()


class VTMatchSourceWrappedMappedTableColumn:
    def __init__(self, mapper, table_column):
        super().__init__(mapper, table_column)

    def get_column_display_name(self, settings):
        return "Source " + super().get_column_display_name(settings)

    def get_column_description(self):
        return super().get_column_name() + " (for a match's source address)"

    def get_column_name(self):
        return "Source " + super().get_column_name()
