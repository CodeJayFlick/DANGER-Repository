class TargetBitfieldDataType:
    def __init__(self):
        pass

    class DefaultTargetBitfieldDataType(TargetBitfieldDataType):
        def __init__(self, field_type: 'TargetDataType', least_bit_position: int, bit_length: int):
            self.field_type = field_type
            self.least_bit_position = least_bit_position
            self.bit_length = bit_length

        @property
        def field_type(self) -> 'TargetDataType':
            return self._field_type

        @property
        def least_bit_position(self) -> int:
            return self._least_bit_position

        @property
        def bit_length(self) -> int:
            return self._bit_length


class TargetBitfieldDataType:
    pass
