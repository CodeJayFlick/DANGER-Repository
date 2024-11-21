Here is the translation of the Java code into Python:

```Python
class FileByteBlock:
    def __init__(self, b):
        self.buf = b
        self.converter = LittleEndianDataConverter()

    def get_location_representation(self, big_index):
        index = int(big_index)
        if 0 <= index < len(self.buf):
            return str(index).rjust(8)
        else:
            return None

    @property
    def max_location_representation_size(self):
        return 8

    def get_index_name(self):
        return "Bytes"

    def get_length(self):
        return BigInteger(str(len(self.buf)))

    def get_byte(self, big_index):
        index = int(big_index)
        if 0 <= index < len(self.buf):
            return self.buf[index]
        else:
            return 0

    def get_int(self, big_index):
        index = int(big_index)
        if 0 <= index < len(self.buf):
            b = bytes([self.buf[i] for i in range(index, index + 4)])
            return self.converter.get_int(b)
        else:
            return 0

    def get_long(self, big_index):
        index = int(big_index)
        if 0 <= index < len(self.buf):
            b = bytes([self.buf[i] for i in range(index, index + 8)])
            return self.converter.get_long(b)
        else:
            return 0

    def set_byte(self, big_index, value):
        index = int(big_index)
        if 0 <= index < len(self.buf):
            self.buf[index] = value
        pass

    def set_int(self, big_index, value):
        index = int(big_index)
        if 0 <= index < len(self.buf):
            b = bytes([0 for _ in range(4)])
            self.converter.put_int(b, 0, value)
            start = index
            end = min(index + 4, len(self.buf))
            self.buf[start:end] = list(b)

    def set_long(self, big_index, value):
        index = int(big_index)
        if 0 <= index < len(self.buf):
            b = bytes([0 for _ in range(8)])
            self.converter.put_long(b, 0, value)
            start = index
            end = min(index + 8, len(self.buf))
            self.buf[start:end] = list(b)

    def is_editable(self):
        return False

    @property
    def big_endian(self):
        return True

    def set_big_endian(self, big_endian):
        if self.big_endian != big_endian:
            self.big_endian = big_endian
            self.converter = LittleEndianDataConverter() if not big_endian else BigEndianDataConverter()

    def get_alignment(self, radix):
        return 0

    @property
    def bytes(self):
        return self.buf


class DataConverter:
    def __init__(self):
        pass

    def put_int(self, b, offset, value):
        raise NotImplementedError("Method not implemented")

    def get_int(self, b):
        raise NotImplementedError("Method not implemented")


class LittleEndianDataConverter(DataConverter):

    @staticmethod
    def getInstance():
        return LittleEndianDataConverter()


class BigEndianDataConverter(DataConverter):

    @staticmethod
    def getInstance():
        return BigEndianDataConverter()
```

Please note that the Python code does not include all the methods and properties from the Java code. Some of them are missing or have been modified to fit Python's syntax and semantics.