Here is the translation of the Java code into Python:

```Python
import crc32c
from io import BytesIO
from struct import unpack

class SparseImageDecompressor:
    def __init__(self, provider, os):
        self.reader = BinaryReader(provider)
        self.crc = crc32c.CRC32()
        self.temp_fos = BytesIO()

    def decompress(self, monitor):
        sparse_header = SparseHeader(self.reader)

        if sparse_header.major_version != 1:
            raise IOException("Unsupported major version number.")

        self.block_size = sparse_header.blk_sz

        total_blocks = 0
        monitor.set_maximum(sparse_header.total_chunks)
        monitor.set_progress(0)

        for i in range(sparse_header.total_chunks):
            if monitor.check_cancelled():
                break

            chunk_header = ChunkHeader(self.reader)
            chunk_type = chunk_header.chunk_type
            chunk_size = chunk_header.chunk_sz

            if chunk_type == 1:
                self.process_raw_chunk(chunk_size, monitor)
                total_blocks += chunk_size
            elif chunk_type == 2:
                self.process_fill_chunk(chunk_size, monitor)
                total_blocks += chunk_size
            elif chunk_type == 3:
                self.process_skip_chunk(chunk_size, monitor)
                total_blocks += chunk_size
            else:
                raise IOException("Unknown chunk type: " + str(chunk_type))

            monitor.increment_progress(1)

        long_total_size = (total_blocks * sparse_header.blk_sz)
        monitor.set_message("Total bytes: " + str(long_total_size))

    def process_crc_chunk(self):
        file_crc = self.reader.read_int()
        value = self.crc.value
        if file_crc != value:
            raise IOException("Computed crc (" + hex(value) +
                               ") did not match the expected crc (" + hex(file_crc) + ").")

    def process_skip_chunk(self, blocks, monitor):
        length = (blocks * self.block_size)
        buffer_size = 1024*1024
        if length > buffer_size:
            for i in range((length // buffer_size)):
                if monitor.check_cancelled():
                    break

                self.temp_fos.write(b'\0' * buffer_size)

        size = int(length % buffer_size)
        bytes_to_write = bytearray(size)
        self.temp_fos.write(bytes_to_write)

    def process_fill_chunk(self, blocks, monitor):
        fill_int = self.reader.read_int()
        length = (blocks * self.block_size)
        buffer_size = 1024*1024
        if length > buffer_size:
            for i in range((length // buffer_size)):
                if monitor.check_cancelled():
                    break

                bytes_to_write = bytearray(buffer_size)
                fill_array(fill_int, bytes_to_write)
                self.temp_fos.write(bytes_to_write)

        size = int(length % buffer_size)
        bytes_to_write = bytearray(size)
        fill_array(fill_int, bytes_to_write)
        self.crc.update(bytes_to_write)
        self.temp_fos.write(bytes_to_write)

    def process_raw_chunk(self, blocks, monitor):
        length = (blocks * self.block_size)
        while length > 0:
            if monitor.check_cancelled():
                break

            bytes_to_read = min(length, buffer_size)
            data = self.reader.read_next_bytes(bytes_to_read)
            self.crc.update(data)
            self.temp_fos.write(data)
            length -= bytes_to_read


def fill_array(fill_int, dest):
    for src_index in range(len(dest)):
        if src_index >= 4:
            src_index %= 4

        dest[src_index] = (fill_int >> ((3 - src_index) * 8)) & 0xff
```

Please note that the above Python code is a direct translation of your Java code and might not be optimal or idiomatic for Python.