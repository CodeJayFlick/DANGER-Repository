class ReferenceFromAddressTableColumn:
    def get_column_display_name(self):
        return self.get_column_name()

    def get_column_name(self):
        return "From Location"

    def get_value(self, row_object: 'ReferenceAddressPair', settings=None, program=None) -> 'Address':
        if not isinstance(row_object, ReferenceAddressPair):
            raise ValueError("Invalid reference address pair")
        return row_object.get_source()

    def get_program_location(self, row_object: 'ReferenceAddressPair', settings=None, program=None) -> 'ProgramLocation':
        value = self.get_value(row_object, None, program)
        if not isinstance(value, Address):
            raise ValueError("Invalid address")
        return ProgramLocation(program, value)

class ReferenceAddressPair:
    def get_source(self) -> 'Address':
        # implement this method
        pass

class ProgramLocation:
    def __init__(self, program: 'Program', location: 'Address'):
        self.program = program
        self.location = location

class Address:
    pass

# usage example:

reference_address_pair = ReferenceAddressPair()
program_location_table_column = ReferenceFromAddressTableColumn()

print(program_location_table_column.get_value(reference_address_pair, None, "your_program"))
