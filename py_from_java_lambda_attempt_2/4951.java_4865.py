Here's your requested translation:

```Python
class OmfExternalSymbol:
    def __init__(self, is_static):
        self.is_static = is_static

    @classmethod
    def from_reader(cls, reader, is_static) -> 'OmfExternalSymbol':
        instance = cls(is_static)
        instance.read_record_header(reader)
        max_index = reader.tell() + instance.get_record_length() - 1
        symbol_list = []

        while reader.tell() < max_index:
            name = OmfRecord.read_string(reader)
            type_ = OmfRecord.read_index(reader)
            subrec = OmfSymbol(name, type_, 0, 0, 0)
            symbol_list.append(subrec)

        instance.read_check_sum_byte(reader)
        instance.symbol = [subrec for subrec in symbol_list]

    @property
    def symbols(self):
        return self.symbol

    @property
    def is_static_(self):
        return self.is_static


class OmfRecord:
    @classmethod
    def read_string(cls, reader) -> str:
        # implement this method to read a string from the binary file
        pass

    @classmethod
    def read_index(cls, reader) -> int:
        # implement this method to read an index value from the binary file
        pass


class OmfSymbol:
    def __init__(self, name: str, type_: int, offset1: int, offset2: int, offset3: int):
        self.name = name
        self.type_ = type_
        self.offset1 = offset1
        self.offset2 = offset2
        self.offset3 = offset3

    def __repr__(self) -> str:
        return f'OmfSymbol({self.name}, {self.type_})'
```

Please note that the `OmfRecord` and `Omfsymbol` classes are incomplete, as they require additional methods to read strings and indices from a binary file.