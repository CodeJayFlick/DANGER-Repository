Here is the translation of the Java code into Python:

```Python
class Structure:
    def __init__(self):
        pass

    @staticmethod
    class BitOffsetComparator:
        INSTANCE_LE = None
        INSTANCE_BE = None

        def __init__(self, big_endian=False):
            self.big_endian = big_endian

        def compare(self, o1, o2):
            if isinstance(o1, int):
                return -self.compare(o2, o1)
            dtc = DataTypeComponent()
            bit_offset = o2
            start_bit = 0
            end_bit = 8 * len(dtc) - 1

            if isinstance(o1, BitFieldDataType):
                start_bit = self.get_normalized_bitfield_offset(
                    dtc.offset,
                    dtc.length,
                    o1.bit_size,
                    o1.bit_offset,
                    self.big_endian)
                end_bit += o1.bit_size - 1
            else:
                start_bit = 8 * dtc.offset

            if bit_offset < start_bit:
                return 1
            elif bit_offset > end_bit:
                return -1
            else:
                return 0

        @staticmethod
        def get_normalized_bitfield_offset(byte_offset, storage_size, effective_bit_size,
                                             bit_offset, big_endian):
            offset = 8 * byte_offset
            if effective_bit_size == 0:
                # force zero-length bitfield placement
                effective_bit_size = 1
                if big_endian:
                    bit_offset |= 7
                else:
                    bit_offset &= 0xfffffff8

            if big_endian:
                offset += (8 * storage_size) - effective_bit_size - bit_offset
            else:
                offset += bit_offset
            return offset


class DataTypeComponent:
    def __init__(self):
        pass

    @property
    def offset(self):
        raise NotImplementedError("offset is not implemented")

    @property
    def length(self):
        raise NotImplementedError("length is not implemented")


class BitFieldDataType(DataTypeComponent):
    def __init__(self, bit_size=0, bit_offset=0):
        self.bit_size = bit_size
        self.bit_offset = bit_offset

    @property
    def bit_size(self):
        return self._bit_size

    @bit_size.setter
    def bit_size(self, value):
        if not isinstance(value, int) or value < 1:
            raise ValueError("Bit size must be a positive integer")
        self._bit_size = value


class UndefinedDataType(DataTypeComponent):
    pass
```

Please note that this translation is based on the assumption that `DataType` and its subclasses (`Undefined1DataType`, etc.) are not defined in Java, but their Python counterparts have been provided.