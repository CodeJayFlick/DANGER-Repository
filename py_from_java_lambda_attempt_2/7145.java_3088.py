Here is the translation of the given Java code into Python:

```Python
class StringDataItem:
    MAX_STRING_LEN = 0x200000  # 2Mb'ish

    def __init__(self, string_item=None, reader=None, dex_header=None):
        if string_item and reader and dex_header:
            self.string_length = LEB128.read_unsigned_value(reader)
            self.leb_length = LEB128.get_length()
            null_term_index = get_index_of_byte_value(reader, 0, MAX_STRING_LEN, b'\x00')
            self.actual_length = int(null_term_index - reader.tell() + 1)
            string_bytes = reader.read_nextByteArray(self.actual_length)

            in_stream = io.BytesIO(string_bytes)
            out_chars = [''] * self.string_length
            self.string = ModifiedUTF8.decode(in_stream, out_chars)

    def __init__(self, string):
        if isinstance(string, str):
            self.string = string

    @property
    def string(self):
        return self._string

    def to_data_type(self) -> DataType:
        structure = StructureDataType("string_data_item_" + str(self.actual_length), 0)
        structure.add(ArrayDataType(BYTE, self.leb_length, BYTE.get_length()), "utf16_size", None)
        structure.add(UTF8, self.actual_length, "data", None)
        structure.set_category_path(CategoryPath("/dex/string_data_item"))
        return structure

    @staticmethod
    def get_index_of_byte_value(reader: io.BufferedReader, start_index: int, max_len: int, byte_value_to_find: bytes) -> int:
        max_index = start_index + max_len
        current_index = start_index
        while current_index < max_index:
            b = reader.read(1)
            if b == byte_value_to_find:
                return current_index
            current_index += 1
        return current_index

class LEB128:
    @staticmethod
    def read_unsigned_value(reader: io.BufferedReader) -> int:
        # implementation of reading unsigned value from LE B128 format
        pass

    @staticmethod
    def get_length() -> int:
        # implementation of getting length from LE B128 format
        pass

class ModifiedUTF8:
    @staticmethod
    def decode(in_stream: io.BytesIO, out_chars) -> str:
        # implementation of decoding UTF-8 string
        pass

class StructureDataType(DataType):
    def __init__(self, name: str, offset: int):
        super().__init__()
        self.name = name
        self.offset = offset

class ArrayDataType(DataType):
    def __init__(self, type: bytes, length: int, size: int):
        super().__init__()
        self.type = type
        self.length = length
        self.size = size

class BYTE:
    @staticmethod
    def get_length() -> int:
        # implementation of getting length for byte data type
        pass

class UTF8(DataType):
    @staticmethod
    def get_length() -> int:
        # implementation of getting length for UTF-8 data type
        pass

# Usage example:

reader = io.BufferedReader()
dex_header = None  # or any other required object
string_item = StringDataItem(None, reader, dex_header)
print(string_item.string)

data_type = string_item.to_data_type()
```

Please note that the above Python code is a direct translation of your Java code and may not work as-is. You will need to implement some classes (LEB128, ModifiedUTF8) and methods (get_index_of_byte_value, read_unsigned_value, get_length).