Here is the translation of the Java interface `DataFormatModel` into a Python class:

```Python
class DataFormatModel:
    NEXT_UNIT = -1
    PREVIOUS_UNIT = -1

    def __init__(self):
        pass

    def get_unit_byte_size(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_name(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_help_location(self) -> 'HelpLocation':
        raise NotImplementedError("Method not implemented")

    def get_data_unit_symbol_size(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_byte_offset(self, block: bytes, position: int) -> int:
        raise NotImplementedError("Method not implemented")

    def get_column_position(self, block: bytes, byte_offset: int) -> int:
        raise NotImplementedError("Method not implemented")

    def get_data_representation(self, block: bytes, index: 'BigInteger') -> str:
        raise NotImplementedError("Method not implemented")

    def is_editable(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def replace_value(self, block: bytes, index: 'BigInteger', pos: int, c: chr) -> bool:
        raise NotImplementedError("Method not implemented")

    def get_group_size(self) -> int:
        raise NotImplementedError("Method not implemented")

    def set_group_size(self, group_size: int):
        raise NotImplementedError("Method not implemented")

    def get_unit_delimiter_size(self) -> int:
        raise NotImplementedError("Method not implemented")

    def validate_bytes_per_line(self, bytes_per_line: int) -> bool:
        raise NotImplementedError("Method not implemented")

    def dispose(self):
        pass
```

Note that the Python code does not have direct equivalents for Java's `public`, `int`, `String`, etc. Instead, it uses Python's built-in types and conventions (e.g., using indentation to denote block-level structure).