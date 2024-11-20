Here is the translation of the Java code to Python:
```python
class CoffSymbolAuxTagName:
    def __init__(self, reader):
        self.unused1 = reader.read_next_byte_array(6)
        self.size = reader.read_next_short()
        self.unused2 = reader.read_next_byte_array(4)
        self.next_entry_index = reader.read_next_int()
        self.unused3 = reader.read_next_byte_array(2)

    def get_unused1(self):
        return self.unused1

    def get_size(self):
        return self.size

    def get_unused2(self):
        return self.unused2

    def get_next_entry_index(self):
        return self.next_entry_index

    def get_unused3(self):
        return self.unused3

    def to_data_type(self) -> None:
        try:
            from ghidra.util import struct_converter_util
            return struct_converter_util.to_data_type(self)
        except (Exception,):  # DuplicateNameException and IOException are not defined in Python
            pass
```
Note that I had to make some assumptions about the `BinaryReader` class and its methods, as well as the `StructConverterUtil` class. In Java, these classes seem to be part of a larger framework (Ghidra), but since we're translating to Python, I assumed they would need to be imported or defined separately.

Also, in Python, it's common practice not to throw exceptions explicitly like you do in Java; instead, you can use try-except blocks to catch and handle errors. In this case, I wrapped the `to_data_type` method with a try-catch block that catches any exception (including `DuplicateNameException` and `IOException`, which are not defined in Python).