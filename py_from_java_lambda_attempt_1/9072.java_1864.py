Here is the translation of the Java code into equivalent Python:

```Python
class VTMarkupItemSourceAddressToProgramLocationTableRowMapper:
    def create_mapped_table_column(self, source_column):
        if isinstance(source_column, ProgramLocationTableColumn):
            program_column = source_column
            return VTMarkupItemSourceWrappedMappedProgramLocationTableColumn(self, program_column)
        else:
            return VTMarkupItemSourceWrappedMappedTableColumn(self, source_column)

    def map(self, row_object, program, serviceProvider):
        address = row_object.get_source_address()
        return ProgramLocation(program, address)


class VTMarkupItemSourceWrappedMappedProgramLocationTableColumn:
    def __init__(self, mapper, table_column):
        super().__init__(mapper, table_column, f"VTMarkupItemSource.{table_column.unique_identifier}")

    def get_column_display_name(self, settings):
        return "Source " + super().get_column_display_name(settings)

    def get_column_description(self):
        return super().get_column_name() + " (for a markup items's Source address)"

    def get_column_name(self):
        return f"Source {super().get_column_name()}"


class VTMarkupItemSourceWrappedMappedTableColumn:
    def __init__(self, mapper, table_column):
        super().__init__(mapper, table_column, f"VTMarkupItemSource.{table_column.unique_identifier}")

    def get_column_display_name(self, settings):
        return "Source " + super().get_column_display_name(settings)

    def get_column_description(self):
        return super().get_column_name() + " (for a markup items's Source address)"

    def get_column_name(self):
        return f"Source {super().get_column_name()}"


class ProgramLocation:
    def __init__(self, program, address):
        self.program = program
        self.address = address


class ProgramLocationTableColumn:
    pass  # This class is not implemented in the given Java code.