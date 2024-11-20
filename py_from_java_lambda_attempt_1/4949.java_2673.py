Here's a translation of the Java code into equivalent Python:

```Python
class OmfEnumeratedData:
    def __init__(self):
        self.segment_index = None
        self.data_offset = None
        self.stream_offset = None  # Position in stream where data starts
        self.stream_length = None  # Number of bytes of data

    def read_record_header(self, reader):
        pass  # This method is not implemented here. It's assumed to be a part of the parent class.

    @classmethod
    def read_index(cls, reader):
        return int.from_bytes(reader.read(2), 'big')

    @classmethod
    def read_int2_or_4(cls, reader, has_big_fields=False):
        if has_big_fields:
            return int.from_bytes(reader.read(4), 'big')
        else:
            return int.from_bytes(reader.read(4), 'little')

    def get_segment_index(self):
        return self.segment_index

    @property
    def data_offset(self):
        return self.data_offset

    @data_offset.setter
    def data_offset(self, value):
        self.data_offset = value

    @property
    def stream_length(self):
        return self.stream_length

    @stream_length.setter
    def stream_length(self, value):
        self.stream_length = value

    def __lt__(self, other):
        if isinstance(other, OmfEnumeratedData):
            if self.data_offset < other.data_offset:
                return True
            else:
                return False
        else:
            raise TypeError("Comparing with a non-OmfEnumeratedData object")

    @property
    def stream_offset(self):
        return self.stream_offset

    @stream_offset.setter
    def stream_offset(self, value):
        self.stream_offset = value

    def get_byte_array(self, reader):
        reader.seek(self.stream_offset)
        buffer = reader.read(self.stream_length)
        return buffer

    def is_all_zeroes(self):
        return False  # This method always returns false. It's assumed to be a part of the parent class.
```

This Python code defines an `OmfEnumeratedData` class with similar attributes and methods as in Java. The `read_record_header`, `get_check_sum_byte`, and some other methods are not implemented here, assuming they're parts of the parent class or will be added later.

The comparison method (`__lt__`) is also simplified to compare only on the basis of data offset for simplicity.