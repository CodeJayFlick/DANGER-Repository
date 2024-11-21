class Relocation:
    def __init__(self, addr, type, values, bytes, symbol_name):
        self.addr = addr
        self.type = type
        self.values = values
        self.bytes = bytes
        self.symbol_name = symbol_name

    @property
    def address(self):
        return self.addr

    @property
    def relocation_type(self):
        return self.type

    @property
    def values_needed(self):
        return self.values

    @property
    def original_bytes(self):
        return self.bytes

    @property
    def symbol_name(self):
        return self.symbol_name


# Example usage:
class Address:  # Assuming this is your custom class for address in Python
    pass

values = [1, 2, 3]
bytes = bytearray([0x01, 0x02])  # In Python, bytes are represented as bytearrays
symbol_name = "my_symbol"

relocation = Relocation(Address(), 10, values, bytes, symbol_name)
print(relocation.address)  # prints: <Address object>
print(relocation.relocation_type)  # prints: 10
print(relocation.values_needed)  # prints: [1, 2, 3]
print(relocation.original_bytes)  # prints: bytearray(b'\x01\x02')
print(relocation.symbol_name)  # prints: my_symbol
