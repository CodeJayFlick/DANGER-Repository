class BiDirectionDataType:
    def __init__(self, name: str, negative_length: int, positive_length: int, split_offset: int):
        self.name = name
        self.negative_length = negative_length
        self.positive_length = positive_length
        self.split_offset = split_offset

    @property
    def num_components(self) -> int:
        return 0

    @num_components.setter
    def num_components(self, value: int):
        self.num_components = value

    def validate_data_type(self, data_type: 'DataType') -> None:
        if isinstance(data_type, BitFieldDataType):
            raise ValueError("Bitfield not permitted")

    def get_alignment(self) -> int:
        raise NotImplementedError()

    def repack(self, notify: bool) -> None:
        raise AssertException

    # ... other methods ...

class OffsetComparator:
    def compare(self, o1: object, o2: object) -> int:
        if isinstance(o1, int):
            return -self.compare(o2, o1)
        dtc = (o1,)
        offset = o2
        if offset < dtc[0]:
            return 1
        elif offset > dtc[1]:
            return -1
        return 0

class OrdinalComparator:
    def compare(self, o1: object, o2: object) -> int:
        if isinstance(o1, int):
            return -self.compare(o2, o1)
        dtc = (o1,)
        ordinal = o2
        return dtc[0] - ordinal

class DataTypeComponentImpl:
    def __init__(self, data_type: 'DataType', parent: BiDirectionDataType, length: int, ordinal: int, offset: int):
        self.data_type = data_type
        self.parent = parent
        self.length = length
        self.ordinal = ordinal
        self.offset = offset

class DataType:
    def __init__(self, name: str):
        self.name = name

# ... other classes ...
