Here is the translation of the given Java code into Python:

```Python
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
```

Please note that the `CoffConstants.SYMBOL_SIZEOF` and `struct_converter_util` are not defined in this Python code. You would need to define them or import them from another module for your program to work correctly.

Also, please be aware that translating Java code into Python can sometimes require a good understanding of both languages as well as the specific libraries being used.