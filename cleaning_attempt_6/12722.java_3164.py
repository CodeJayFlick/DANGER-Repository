class IntPropertyMap:
    def __init__(self):
        self.properties = {}

    def add(self, addr: int, value: int) -> None:
        """Add an int value at the specified address."""
        self.properties[addr] = value

    def get_int(self, addr: int) -> int:
        """Get the integer value at the given address. Raises NoValueException if there is no property value at addr."""
        try:
            return self.properties[addr]
        except KeyError as e:
            raise ValueError("No value found for this address") from e
