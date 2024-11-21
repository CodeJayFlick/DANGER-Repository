Here's your Java class translated into a Python class:

```Python
class OmfSymbol:
    def __init__(self, name: str, type_index: int, offset: int, data_type: int, byte_length: int):
        self.symbol_name = name
        self.type_index = type_index
        self.offset = offset
        self.data_type = data_type
        self.byte_length = byte_length

    def get_symbol_name(self) -> str:
        return self.symbol_name

    def get_data_type(self) -> int:
        return self.data_type

    def get_offset(self) -> int:
        return self.offset

    def get_segment_ref(self) -> int:
        return self.segment_ref

    def set_segment_ref(self, val: int):
        self.segment_ref = val

    def set_address(self, addr):
        self.address = addr

    def get_address(self):
        return self.address

    def get_frame_datum(self) -> int:
        return 0
```

Note that Python does not have direct equivalent of Java's private/public access modifiers. However, it is common to use underscore prefix for internal variables and methods in Python (like `_symbol_name` instead of `self.symbol_name`).