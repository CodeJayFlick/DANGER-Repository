class CoffSymbolAuxDefault:
    def __init__(self, reader):
        try:
            self.bytes = reader.read_next_byte_array(CoffConstants.SYMBOL_SIZEOF)
        except Exception as e:
            print(f"An error occurred: {e}")

    def get_bytes(self):
        return self.bytes

    def to_data_type(self):
        try:
            from ghidra.util import struct_converter_util
            return struct_converter_util.to_data_type(self)
        except Exception as e:
            print(f"An error occurred: {e}")
