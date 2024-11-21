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
