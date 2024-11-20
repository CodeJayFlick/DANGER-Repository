class DisplayableListingAddress:
    def __init__(self, program: 'Program', address: int) -> None:
        self.program = program
        self.address = address

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    def get_display_string(self) -> str:
        if self.address is None or self.address == 0:
            return 'NO_ADDRESS'
        location = AddressBasedLocation(self.program, self.address)
        return str(location)

    def __str__(self) -> str:
        return self.get_display_string()

    def compare_to(self, other: 'DisplayableListingAddress') -> int:
        if other is None:
            return 1
        other_address = other.address
        if self.address is None:
            return (other_address == 0) and -1 or 0
        if other_address is None:
            return 1
        return self.address.__eq__(other_address)

class AddressBasedLocation:
    def __init__(self, program: 'Program', address: int) -> None:
        self.program = program
        self.address = address

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

class Program:
    pass  # assuming this is a custom class in your Python codebase

NO_ADDRESS = 'NO_ADDRESS'
