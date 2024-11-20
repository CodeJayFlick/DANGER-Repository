Here is the translation of the given Java code into Python:

```Python
class ViewStringsTableModel:
    def __init__(self):
        self.rows_indexed_by_address = {}

    COLUMNS = {
        'ADDRESS_COL',
        'STRING_VALUE_ COL',
        'STRING_REP_COL',
        'DATA_TYPE_COL',
        'IS_ASCII_COL',
        'CHARSET_COL',
        'HAS_ENCODING_ERROR'
    }

    def is_cell_editable(self, row_index, column_index):
        return self.get_column(column_index) == self.STRING_REP_COL

    def set_value_at(self, value, row_index, column_index):
        if isinstance(value, str):
            program_location = self.get_row_object(row_index)
            ManualStringTranslationService.set_translated_value(program_location, value)

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        for i in range(len(COLUMNS)):
            if COLUMNS[i] == 'ADDRESS_COL':
                column = DataLocationColumn()
            elif COLUMNS[i] == 'STRING_VALUE_ COL':
                column = DataValueColumn()
            elif COLUMNS[i] == 'STRING_REP_COL':
                column = StringRepColumn()
            elif COLUMNS[i] == 'DATA_TYPE_COL':
                column = DataTypeColumn()
            elif COLUMNS[i] == 'IS_ASCII_COL':
                column = IsAsciiColumn()
            elif COLUMNS[i] == 'CHARSET_COL':
                column = CharsetColumn()
            else:
                column = HasEncodingErrorColumn()

            descriptor.add_visible_column(column)

        return descriptor

    def do_load(self, accumulator, monitor):
        self.rows_indexed_by_address.clear()

        program = get_program()
        if not program:
            return

        listing = program.get_listing()

        for data in DefinedDataIterator.defined_strings(program):
            location = create_indexed_string_instance_location(program, data)
            accumulator.add(location)

    def remove_data_instance_at(self, address):
        program_location = self.rows_indexed_by_address.get(address)
        if program_location:
            self.remove_object(program_location)

    def find_equiv_program_location(self, program_location):
        return self.rows_indexed_by_address.get(program_location.address) if program_location else None

    def add_data_instance(self, program, data, monitor):
        for string_instance in DefinedDataIterator.defined_strings(data):
            location = create_indexed_string_instance_location(program, string_instance)
            self.add_object(location)

    class DataLocationColumn:
        def get_column_name(self):
            return 'Location'

        def get_value(self, row_object, settings, program, service_provider):
            return AddressBasedLocation(row_object.program, row_object.address)

        def get_program_location(self, row_object, settings, program, service_provider):
            return row_object

    class DataValueColumn:
        def __init__(self):
            self.renderer = DataValueCellRenderer()

        def get_column_name(self):
            return 'String Value'

        def get_value(self, row_object, settings, program, service_provider):
            data = DataUtilities.get_data_at_location(row_object)
            if isinstance(data, StringDataInstance):
                return data

        def get_program_location(self, row_object, settings, program, service_provider):
            return row_object

    class StringRepColumn:
        def __init__(self):
            self.renderer = StringRepCellRenderer()

        def get_column_name(self):
            return 'String Representation'

        def get_value(self, row_object, settings, program, service_provider):
            data = DataUtilities.get_data_at_location(row_object)
            if isinstance(data, StringDataInstance):
                return data

        def get_program_location(self, row_object, settings, program, service_provider):
            return row_object

    class DataTypeColumn:
        def get_column_name(self):
            return 'Data Type'

        def get_value(self, row_object, settings, program, service_provider):
            data = DataUtilities.get_data_at_location(row_object)
            if not data:
                return ''

            if isinstance(data.get_data_type(), AbstractStringDataType):
                return data.get_data_type().get_mnemonic(settings)

            return str(data.get_data_type())

        def get_program_location(self, row_object, settings, program, service_provider):
            return row_object

    class IsAsciiColumn:
        def get_column_name(self):
            return 'Is Ascii'

        def get_value(self, row_object, settings, program, service_provider):
            data = DataUtilities.get_data_at_location(row_object)
            if not data:
                return False

            string_instance = StringDataInstance(data)

            for code_point in string_instance.string_value.code_points():
                if 0 <= code_point < 0x80:
                    continue
                else:
                    return True

        def get_program_location(self, row_object, settings, program, service_provider):
            return row_object

    class HasEncodingErrorColumn:
        def get_column_name(self):
            return 'Has Encoding Error'

        def get_value(self, row_object, settings, program, service_provider):
            data = DataUtilities.get_data_at_location(row_object)
            if not data:
                return False

            string_instance = StringDataInstance(data)

            for code_point in string_instance.string_value.code_points():
                if code_point == StringUtilities.UNICODE_REPLACEMENT:
                    continue
                else:
                    return True

        def get_program_location(self, row_object, settings, program, service_provider):
            return row_object

    class CharsetColumn:
        def get_column_name(self):
            return 'Charset'

        def get_value(self, row_object, settings, program, service_provider):
            data = DataUtilities.get_data_at_location(row_object)
            if not data:
                return ''

            string_instance = StringDataInstance(data)

            return string_instance.char_set_name

        def get_program_location(self, row_object, settings, program, service_provider):
            return row_object
```

Please note that the provided Java code is quite complex and has many dependencies. This Python translation may not work as-is without additional modifications to handle these dependencies.