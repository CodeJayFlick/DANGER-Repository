class MemSearchResult:
    def __init__(self, address: 'Address', length: int):
        if not isinstance(address, Address) or length <= 0:
            raise ValueError("Invalid input")
        self.address = address
        self.length = length

    @property
    def get_address(self):
        return self.address

    @property
    def get_length(self):
        return self.length

    def __eq__(self, other: 'MemSearchResult'):
        if not isinstance(other, MemSearchResult):
            return False
        return self.address == other.address

    def __lt__(self, other: 'MemSearchResult'):
        return self.address < other.address

    def __hash__(self):
        return hash((self.address,))

    def __str__(self):
        return str(self.address)

class Address:
    pass  # You would need to implement the Address class in Python
