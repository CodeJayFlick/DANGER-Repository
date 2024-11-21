class AddressTableDataTableColumn:
    def __init__(self):
        self.monospaced_renderer = MonospacedRenderer()

    class MonospacedRenderer:
        def configure_font(self, table, model, column):
            pass  # Set font to fixed-width font

        def get_filter_string(self, t, settings):
            return t

    def get_column_display_name(self, settings):
        return self.get_column_name()

    def get_column_name(self):
        return "Data (Hex/Ascii)"

    def get_value(self, row_object, settings, program, service_provider):
        try:
            return str(row_object.get_table_type_string(program.get_memory()))
        except Exception as e:
            raise ValueError(str(e))

    def get_program_location(self, row_object, settings, program, service_provider):
        return ProgramLocation(program, row_object.get_top_address())

class ProgramLocation:
    def __init__(self, program, address):
        self.program = program
        self.address = address

# You can use the class like this:

column = AddressTableDataTableColumn()
print(column.get_column_name())  # prints "Data (Hex/Ascii)"
