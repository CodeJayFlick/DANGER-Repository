Here is the translation of the Java code into Python:

```Python
import logging
from typing import List

class LongRleDecoder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.current_value = 0
        self.is_length_and_bit_width_readed = False
        self.mode = None
        self.bit_packing_num = 0
        self.current_buffer: List[int] = []
        self.packer = LongPacker()

    def read_long(self, buffer):
        if not self.is_length_and_bit_width_readed:
            self.read_length_and_bit_width(buffer)
        
        if self.current_count == 0:
            try:
                self.read_next()
            except Exception as e:
                self.logger.error(f"tsfile-encoding IntRleDecoder: error occurs when reading all encoding number, length {self.length}, bit width {self.bit_width}", e)

        self.current_count -= 1
        result = None
        if self.mode == "rle":
            result = self.current_value
        elif self.mode == "bit_packed":
            result = self.current_buffer[self.bit_packing_num - self.current_count - 1]
        
        if not self.has_next_package():
            self.is_length_and_bit_width_readed = False
        
        return result

    def init_packer(self):
        self.packer = LongPacker(self.bit_width)

    def read_number_in_rle(self) -> None:
        self.current_value = ReadWriteForEncodingUtils.read_long_little_endian_padded_on_bit_width(buffer, self.bit_width)

    def read_bit_packing_buffer(self, bit_packed_group_count: int, last_bit_packed_num: int):
        self.current_buffer = [0] * (bit_packed_group_count * TSFileConfig.RLE_MIN_REPEATED_NUM)
        bytes = bytearray(bit_packed_group_count * self.bit_width)
        bytes_to_read = min(len(bytes), len(buffer))
        buffer.get_bytes_into(bytes, 0, bytes_to_read)

        # save all long values in current_buffer
        self.packer.unpack_all_values(bytes, bytes_to_read, self.current_buffer)


class LongPacker:
    def __init__(self, bit_width):
        pass

    def unpack_all_values(self, buffer: bytearray, length: int, result_list: List[int]) -> None:
        pass


def read_length_and_bit_width(buffer) -> None:
    # implement this method
    pass


def read_next() -> None:
    # implement this method
    pass


def has_next_package() -> bool:
    # implement this method
    pass

# usage example
decoder = LongRleDecoder()
buffer = bytearray(1024)
result = decoder.read_long(buffer)
```

Please note that the above Python code is not a direct translation of Java to Python. It's more like an implementation based on the provided Java code, as some parts are missing in the original Java code (like `LongPacker` class and methods).