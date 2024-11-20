import logging
from typing import List

class IntRleDecoder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.current_value = 0
        self.is_length_and_bit_width_readed = False
        self.mode = None
        self.bit_packing_num = 0
        self.byte_cache = bytearray()

    def read_boolean(self, buffer: bytes) -> bool:
        return self.read_int(buffer) == 0

    def read_int(self, buffer: bytes) -> int:
        if not self.is_length_and_bit_width_readed:
            self.read_length_and_bit_width(buffer)
        if self.current_count == 0:
            try:
                self.read_next()
            except Exception as e:
                self.logger.error("Error occurred when reading encoding numbers")
        self.current_count -= 1
        result = None
        match self.mode:
            case "RLE":
                result = self.current_value
            case "BIT_PACKED":
                result = self.current_buffer[self.bit_packing_num - self.current_count - 1]
            case _:
                raise TsFileDecodingException("Invalid mode")
        if not self.has_next_package():
            self.is_length_and_bit_width_readed = False
        return result

    def init_packer(self):
        self.packer = IntPacker(self.bit_width)

    def read_number_in_rle(self) -> int:
        self.current_value = ReadWriteForEncodingUtils.read_int_little_endian_padded_on_bit_width(
            self.byte_cache, self.bit_width
        )

    def read_bit_packing_buffer(self, bit_packed_group_count: int, last_bit_packed_num: int):
        self.current_buffer = [0] * (bit_packed_group_count * TSFileConfig.RLE_MIN_REPEATED_NUM)
        bytes_to_read = bit_packed_group_count * self.bit_width
        if bytes_to_read > len(self.byte_cache):
            bytes_to_read = len(self.byte_cache)
        self.byte_cache.getbytes(0, bytes_to_read)

        # save all int values in current_buffer
        self.packer.unpack_all_values(
            self.byte_cache[:bytes_to_read], bytes_to_read, self.current_buffer
        )

    def read_length_and_bit_width(self, buffer: bytes):
        pass  # implement this method

    def read_next(self) -> None:
        pass  # implement this method

    def has_next_package(self) -> bool:
        return False  # implement this method

class TsFileDecodingException(Exception):
    pass
