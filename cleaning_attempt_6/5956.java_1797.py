class ReferenceToAddressTableColumn:
    def get_column_display_name(self):
        return self.get_column_name()

    def get_column_name(self):
        return "To Location"

    def get_value(self, row_object: 'ReferenceAddressPair', settings=None) -> 'Address':
        return row_object.destination

    def get_program_location(self, row_object: 'ReferenceAddressPair', settings=None, program='Program') -> 'ProgramLocation':
        address = self.get_value(row_object)
        return ProgramLocation(program, address)

class ReferenceAddressPair:
    pass  # placeholder for the Java class

class Address:
    pass  # placeholder for the Java class

class ProgramLocation:
    def __init__(self, program: str, address: 'Address'):
        self.program = program
        self.address = address

# Example usage:
row_object = ReferenceAddressPair()  # create an instance of the Python equivalent of ReferenceAddressPair
program_location = ReferenceToAddressTableColumn().get_program_location(row_object)
print(program_location)  # prints a ProgramLocation object with the To Location value
