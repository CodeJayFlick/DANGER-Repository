Here is the equivalent Python code:

```Python
class SparseHeader:
    def __init__(self, provider):
        self.magic = 0xED26FF3A
        self.major_version = 0
        self.minor_version = 0
        self.file_hdr_sz = 0
        self.chunk_hdr_sz = 0
        self.blk_sz = 0
        self.total_blks = 0
        self.total_chunks = 0
        self.image_checksum = 0

    def from_binary_reader(self, reader):
        self.magic = int.from_bytes(reader.read(4), 'little')
        self.major_version = int.from_bytes(reader.read(2), 'little')
        self.minor_version = int.from_bytes(reader.read(2), 'little')
        self.file_hdr_sz = int.from_bytes(reader.read(2), 'little')
        self.chunk_hdr_sz = int.from_bytes(reader.read(2), 'little')
        self.blk_sz = int.from_bytes(reader.read(4), 'little')
        self.total_blks = int.from_bytes(reader.read(4), 'little')
        self.total_chunks = int.from_bytes(reader.read(4), 'little')
        self.image_checksum = int.from_bytes(reader.read(4), 'little')

    def get_magic(self):
        return self.magic

    def get_major_version(self):
        return self.major_version

    def get_minor_version(self):
        return self.minor_version

    def get_file_hdr_sz(self):
        return self.file_hdr_sz

    def get_chunk_hdr_sz(self):
        return self.chunk_hdr_sz

    def get_blk_sz(self):
        return self.blk_sz

    def get_total_blks(self):
        return self.total_blks

    def get_total_chunks(self):
        return self.total_chunks

    def get_image_checksum(self):
        return self.image_checksum
```

Note that Python does not have a direct equivalent to Java's `StructConverter` or `DataType`. The above code is simply the translation of your original Java code into Python.