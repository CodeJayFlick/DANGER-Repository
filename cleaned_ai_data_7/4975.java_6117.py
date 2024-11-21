class CliBlob:
    PATH = "/PE/CLI/Blobs"

    def __init__(self, stream_index: int, reader):
        self.stream_index = stream_index
        self.reader = reader

        self.blob_offset = reader.tell()
        self.contents_size = self.parse_coded_size(reader)
        self.contents_offset = reader.tell()
        reader.seek(self.contents_offset + self.contents_size)

    def __init__(self, blob: 'CliBlob'):
        this.stream_index = blob.stream_index
        this.reader = blob.reader
        this.blob_offset = blob.blob_offset
        this.contents_size = blob.contents_size
        this.contents_offset = blob.contents_offset

    @staticmethod
    def parse_coded_size(reader):
        one_byte = reader.read(1)[0]
        size = 0
        if (one_byte & 0x80) == 0:
            size = one_byte & 0xff
        elif (one_byte & 0xC0) == 0x80:
            two_bytes = reader.read(2)
            size = ((one_byte & ~0xC0) & 0xFF) << 8 | two_bytes[1]
        elif (one_byte & 0xE0) == 0xC0:
            two_bytes = reader.read(2)
            three_bytes = reader.read(2)
            four_bytes = reader.read(4)
            size = ((one_byte & ~0xE0) & 0xFF) << 24 | (two_bytes[1] << 16) | (three_bytes[1] << 8) | four_bytes[3]
        return size

    def get_size(self):
        return self.contents_offset - self.blob_offset + self.contents_size

    def get_contents_reader(self):
        contents_reader = BinaryReader(self.reader.get_byte_provider(), False)
        contents_reader.seek(self.contents_offset)
        return contents_reader

    @property
    def stream_index(self):
        return self._stream_index

    @stream_index.setter
    def stream_index(self, value: int):
        self._stream_index = value

    @property
    def reader(self):
        return self._reader

    @reader.setter
    def reader(self, value):
        self._reader = value

    # ... other methods ...

class BinaryReader:
    def __init__(self, byte_provider, is_little_endian=False):
        self.byte_provider = byte_provider
        self.is_little_endian = is_little_endian

    def read(self, size: int) -> bytes:
        return self.byte_provider.read(size)

    def tell(self) -> int:
        # implement this method to get the current position in the file
        pass

    def seek(self, offset: int):
        # implement this method to set the current position in the file
        pass

class DataType:
    pass

# ... other classes and methods ...
