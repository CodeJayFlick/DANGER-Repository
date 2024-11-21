Here is the translation of the Java code into Python:

```Python
import logging
from io import BytesIO
from typing import Union

class TimePageWriter:
    def __init__(self, time_encoder: 'Encoder', compressor: 'ICompressor') -> None:
        self.time_out = BytesIO()
        self.time_encoder = time_encoder
        self.statistics = TimeStatistics()
        self.compressor = compressor

    def write(self, time: int) -> None:
        self.time_encoder.encode(time, self.time_out)
        self.statistics.update(time)

    def write_timestamps(self, timestamps: list[int], batch_size: int) -> None:
        for i in range(batch_size):
            self.time_encoder.encode(timestamps[i], self.time_out)
        self.statistics.update(timestamps, batch_size)

    def prepare_end_write_one_page(self) -> None:
        self.time_encoder.flush(self.time_out)

    def get_uncompressed_bytes(self) -> Union[bytes, bytearray]:
        self.prepare_end_write_one_page()
        buffer = BytesIO(self.time_out.getvalue())
        return buffer

    def write_page_header_and_data_into_buff(self, page_buffer: 'PublicBAOS', first: bool) -> int:
        if not self.statistics.get_count():
            return 0
        page_data = self.get_uncompressed_bytes()
        uncompressed_size = len(page_data.getvalue())
        compressed_size = None
        compressed_bytes = None

        if self.compressor.get_type() == CompressionType.UNCOMPRESSED:
            compressed_size = uncompressed_size
        else:
            compressed_bytes = bytearray(self.compressor.get_max_bytes_for_compression(uncompressed_size))
            compressed_size = self.compressor.compress(
                page_data.getvalue(), 0, uncompressed_size, compressed_bytes)

        # write the page header to IOWriter
        size_without_statistic = 0
        if first:
            size_without_statistic += ReadWriteForEncodingUtils.write_unsigned_var_int(uncompressed_size, page_buffer)
            size_without_statistic += ReadWriteForEncodingUtils.write_unsigned_var_int(compressed_size, page_buffer)
        else:
            ReadWriteForEncodingUtils.write_unsigned_var_int(uncompressed_size, page_buffer)
            ReadWriteForEncodingUtils.write_unsigned_var_int(compressed_size, page_buffer)
            self.statistics.serialize(page_buffer)

        # write page content to temp PBAOS
        logging.trace("start to flush a time page data into buffer, buffer position {}", page_buffer.get_position())
        if self.compressor.get_type() == CompressionType.UNCOMPRESSED:
            try:
                channel = BytesIO()
                channel.write(page_data.getvalue())
            except Exception as e:
                print(f"Error: {e}")
        else:
            page_buffer.write(compressed_bytes, 0, compressed_size)
        logging.trace("finish flushing a time page data into buffer, buffer position {}", page_buffer.get_position())

        return size_without_statistic

    def estimate_max_mem_size(self) -> int:
        return len(self.time_out.getvalue()) + self.time_encoder.get_max_byte_size()

    def reset(self):
        self.time_out.reset()
        self.statistics = TimeStatistics()

    @property
    def time_encoder(self):
        return self._time_encoder

    @time_encoder.setter
    def time_encoder(self, value: 'Encoder'):
        self._time_encoder = value

    @property
    def statistics(self) -> Union[TimeStatistics, None]:
        return self._statistics

    @statistics.setter
    def statistics(self, value: TimeStatistics):
        self._statistics = value

class PublicBAOS:
    pass

class Encoder:
    pass

class ICompressor:
    pass

class CompressionType:
    UNCOMPRESSED = "UNCOMPRESSED"

class TimeStatistics:
    pass

def ReadWriteForEncodingUtils():
    # This is a utility class and does not have any specific implementation
    pass
```

Please note that this translation assumes the following:

- The `Encoder` class has an `encode` method.
- The `ICompressor` interface has methods for compression and decompression, as well as properties like `get_type()` and `get_max_bytes_for_compression()`.
- The `TimeStatistics` class has methods to update statistics and serialize them.
- The `PublicBAOS` class is a simple buffer that can be written into.

The translation also assumes the following Python-specific constructs:

- Use of type hints for method parameters and return types (e.g., `(time_encoder: 'Encoder', compressor: 'ICompressor') -> None`)
- Use of f-strings for formatting strings in logging statements
- Use of `BytesIO` to create a buffer that can be written into
- Use of the `@property` decorator to define getter and setter methods for attributes