Here is the translation of the Java code into Python:

```Python
import logging
from typing import Any, Dict, List

class PageWriter:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.time_encoder: Any = None
        self.value_encoder: Any = None
        self.compressor: Any = None
        self.statistics: Any = None
        self.time_out: bytearray = bytearray()
        self.value_out: bytearray = bytearray()

    def write(self, time: int, value: bool) -> None:
        if not isinstance(time, int):
            raise TypeError("Time must be an integer")
        if not isinstance(value, bool):
            raise TypeError("Value must be a boolean")

        self.time_encoder.encode(time, self.time_out)
        self.value_encoder.encode(int(value), self.value_out)
        self.statistics.update(time, value)

    def write(self, time: int, value: int) -> None:
        if not isinstance(time, int):
            raise TypeError("Time must be an integer")
        if not isinstance(value, int):
            raise TypeError("Value must be an integer")

        self.time_encoder.encode(time, self.time_out)
        self.value_encoder.encode(value, self.value_out)
        self.statistics.update(time, value)

    def write(self, time: int, value: float) -> None:
        if not isinstance(time, int):
            raise TypeError("Time must be an integer")
        if not isinstance(value, (int, float)):
            raise TypeError("Value must be a number")

        self.time_encoder.encode(time, self.time_out)
        self.value_encoder.encode(int(value), self.value_out)
        self.statistics.update(time, value)

    def write(self, time: int, value: str) -> None:
        if not isinstance(time, int):
            raise TypeError("Time must be an integer")
        if not isinstance(value, str):
            raise TypeError("Value must be a string")

        self.time_encoder.encode(time, self.time_out)
        self.value_encoder.encode(len(value).encode('utf-8'), self.value_out)
        for char in value:
            self.value_encoder.encode(ord(char), self.value_out)
        self.statistics.update(time, len(value))

    def write(self, time: int, values: List[int]) -> None:
        if not isinstance(time, int):
            raise TypeError("Time must be an integer")
        if not all(isinstance(val, int) for val in values):
            raise TypeError("Values must be integers")

        self.time_encoder.encode(time, self.time_out)
        for value in values:
            self.value_encoder.encode(value, self.value_out)
        self.statistics.update([time] * len(values), values)

    def prepare_end_write_one_page(self) -> None:
        self.time_encoder.flush(self.time_out)
        self.value_encoder.flush(self.value_out)

    def get_uncompressed_bytes(self) -> bytearray:
        self.prepare_end_write_one_page()
        uncompressed_size = len(self.time_out) + len(self.value_out) + 4
        buffer = bytearray(uncompressed_size)
        ReadWriteForEncodingUtils.write_unsigned_var_int(len(self.time_out), buffer)
        buffer[:len(self.time_out)] = self.time_out[:]
        buffer[len(self.time_out):] = self.value_out[:]
        return buffer

    def write_page_header_and_data_into_buff(self, page_buffer: bytearray, first: bool) -> int:
        if not isinstance(page_buffer, bytearray):
            raise TypeError("Page Buffer must be a byte array")
        if not isinstance(first, bool):
            raise TypeError("First must be a boolean")

        uncompressed_size = len(self.time_out) + len(self.value_out)
        compressed_size = 0
        compressed_bytes = None

        if self.compressor.get_type() == CompressionType.UNCOMPRESSED:
            compressed_size = uncompressed_size
        else:
            compressed_bytes = bytearray(self.compressor.max_bytes_for_compression(uncompressed_size))
            compressed_size = self.compressor.compress(
                self.time_out + self.value_out, 0, len(self.time_out) + len(self.value_out), compressed_bytes)

        if first:
            size_without_statistic = ReadWriteForEncodingUtils.write_unsigned_var_int(uncompressed_size, page_buffer)
            size_without_statistic += ReadWriteForEncodingUtils.write_unsigned_var_int(compressed_size, page_buffer)
        else:
            ReadWriteForEncodingUtils.write_unsigned_var_int(uncompressed_size, page_buffer)
            ReadWriteForEncodingUtils.write_unsigned_var_int(compressed_size, page_buffer)
            self.statistics.serialize(page_buffer)

        if compressed_bytes is not None:
            page_buffer.extend(compressed_bytes[:compressed_size])
        return size_without_statistic

    def estimate_max_mem_size(self) -> int:
        return len(self.time_out) + len(self.value_out) + self.time_encoder.max_byte_size() + self.value_encoder.max_byte_size()

    def reset(self, measurement_schema: Any) -> None:
        if not isinstance(measurement_schema, dict):
            raise TypeError("Measurement Schema must be a dictionary")

        self.time_out = bytearray()
        self.value_out = bytearray()
        self.statistics = Statistics.get_stats_by_type(measurement_schema['type'])

    def set_time_encoder(self, encoder: Any) -> None:
        if not isinstance(encoder, dict):
            raise TypeError("Encoder must be a dictionary")
        self.time_encoder = encoder

    def set_value_encoder(self, encoder: Any) -> None:
        if not isinstance(encoder, dict):
            raise TypeError("Encoder must be a dictionary")
        self.value_encoder = encoder

    def init_statistics(self, data_type: TSDataType) -> None:
        self.statistics = Statistics.get_stats_by_type(data_type)

    def get_point_number(self) -> int:
        return self.statistics.count()

    def get_statistics(self) -> Any:
        return self.statistics
```

Note that I've made some assumptions about the types of variables and functions, as well as how certain methods should behave. If these are incorrect or if you need further modifications, please let me know!