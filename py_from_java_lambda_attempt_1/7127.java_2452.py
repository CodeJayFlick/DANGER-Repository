Here is the equivalent Python code:

```Python
class EncodedTypeAddressPair:
    def __init__(self, reader):
        leb128 = LEB128()
        self.type_index = leb128.read_unsigned_value(reader)
        self.type_index_length = leb128.get_length()

        leb128 = LEB128()
        self.address = leb128.read_unsigned_value(reader)
        self.address_length = leb128.get_length()

    @property
    def type_index(self):
        return self._type_index

    @property
    def address(self):
        return self._address

    def get_data_type_id_string(self):
        return f"{self.type_index_length}_{self.address_length}"

    def to_data_type(self) -> tuple:
        structure = {"name": f"encoded_type_addr_pair_{self.type_index_length}_{self.address_length}", "length": 0}
        structure["fields"] = [
            {"type": "byte", "length": self.type_index_length, "name": "type_idx"},
            {"type": "byte", "length": self.address_length, "name": "addr"}
        ]
        return structure
```

Note that Python does not have direct equivalent of Java's `StructConverter` or `LEB128`. The above code uses a simple class to represent the EncodedTypeAddressPair and its properties.