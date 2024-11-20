class AddressTableColumn:
    def get_column_display_name(self):
        return self.get_column_name()

    def get_column_name(self):
        return "Location"

    def get_value(self, row_object: int, settings=None) -> 'AddressBasedLocation':
        if not isinstance(row_object, int):
            raise ValueError("row_object must be an integer")
        program = Program()  # Assuming this is a class that represents the program
        return AddressBasedLocation(program, row_object)

    def get_program_location(self, row_object: int, settings=None) -> 'ProgramLocation':
        if not isinstance(row_object, int):
            raise ValueError("row_object must be an integer")
        program = Program()  # Assuming this is a class that represents the program
        return AddressFieldLocation(program, row_object)

    def get_column_preferred_width(self):
        return 200

class AddressBasedLocation:
    def __init__(self, program: 'Program', address: int) -> None:
        self.program = program
        self.address = address

class ProgramLocation:
    pass

class AddressFieldLocation(ProgramLocation):
    def __init__(self, program: 'Program', address: int) -> None:
        super().__init__()
        self.program = program
        self.address = address

class Program:
    pass
