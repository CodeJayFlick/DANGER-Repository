Here is the translation of the Java code to Python:
```
class BitRangeSymbol:
    def __init__(self, location):
        pass  # For use with restore_xml (no equivalent in Python)

    def __init__(self, location, name, var_node_symbol, bit_offset, num_bits):
        self.location = location
        self.name = name
        self.var_sym = var_node_symbol
        self.bit_off = bit_offset
        self.num_bits = num_bits

    @property
    def parent_symbol(self):
        return self.var_sym

    @property
    def bit_offset(self):
        return self.bit_off

    @property
    def num_bits(self):
        return self.num_bits

class VarnodeSymbol:
    pass  # No equivalent in Python, just a placeholder for now

symbol_type = enum('bitrange_symbol', 'other_symbols')

def get_symbol_type():
    return symbol_type.bitrange_symbol
```
Note that I had to make some simplifications and assumptions when translating the code:

* The `Location` class is not present in Java, so I removed it. In Python, you could use a custom class or a built-in type like `str`.
* The `SleighSymbol` class is also missing from Java, but since we're only interested in the `BitRangeSymbol` subclass, I left out any references to this class.
* The `VarnodeSymbol` class was not translated as it seems to be used internally within the original code.