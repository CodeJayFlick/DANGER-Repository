Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Any

class RleEncoder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.values: List[Any] = []
        self.bit_width: int = 0
        self.repeat_count: int = 0
        self.bit_packed_group_count: int = 0
        self.num_buffered_values: int = 0
        self.is_bit_pack_run: bool = False
        self.pre_value: Any = None
        self.buffered_values: List[Any] = []
        self.is_bit_width_saved: bool = False
        self.byte_cache: bytearray = bytearray()

    def reset(self):
        self.num_buffered_values = 0
        self.repeat_count = 0
        self.bit_packed_group_count = 0
        self.values.clear()
        self.buffered_values.clear()
        self.is_bit_pack_run = False
        self.is_bit_width_saved = False
        self.byte_cache.reset()

    def flush(self, out: bytearray) -> None:
        last_bit_packed_num = self.num_buffered_values
        if self.repeat_count >= TSFileConfig.RLE_MIN_REPEATED_NUM:
            try:
                self.write_rle_run()
            except Exception as e:
                self.logger.error(f"Error occurs when writing nums to OutputStram: {e}")
                raise

        elif self.num_buffered_values > 0:
            self.clear_buffer()
            self.write_or_append_bit_packed_run()
            self.end_previous_bit_packed_run(last_bit_packed_num)

        else:
            self.end_previous_bit_packed_run(TSFileConfig.RLE_MIN_REPEATED_NUM)

        # write length
        ReadWriteForEncodingUtils.write_unsigned_var_int(len(self.byte_cache), out)
        self.byte_cache.tofile(out)
        self.reset()

    def encode_value(self, value: Any) -> None:
        if not self.is_bit_width_saved:
            # save bit width in header,
            # prepare for read
            self.bit_width = len(self.values[0].__str__().encode())
            self.is_bit_width_saved = True

        if value == self.pre_value:
            self.repeat_count += 1
            if self.repeat_count >= TSFileConfig.RLE_MIN_REPEATED_NUM and self.repeat_count <= TSFileConfig.RLE_MAX_REPEATED_NUM:
                # value occurs more than RLE_MIN_REPEATED_NUM times but less than EncodingConfig.RLE_MAX_REPEATED_NUM
                # we'll use rle, so just keep on counting repeats for now
                # we'll write current value to OutputStream when we encounter a different value
                return

            elif self.repeat_count == TSFileConfig.RLE_MAX_REPEATED_NUM + 1:
                # value occurs more than EncodingConfig.RLE_MAX_REPEATED_NUM
                # we'll write current rle run to stream and keep on counting current value
                self.repeat_count = TSFileConfig.RLE_MAX_REPEATED_NUM
                try:
                    self.write_rle_run()
                    self.logger.debug("tsfile-encoding RleEncoder: write full rle run to stream")
                except Exception as e:
                    self.logger.error(f"Error occurs when writing full rle run to OutputStram: {e}")

                self.repeat_count = 1
                self.pre_value = value

        else:
            # we encounter a different value
            if self.repeat_count >= TSFileConfig.RLE_MIN_REPEATED_NUM:
                try:
                    self.write_rle_run()
                except Exception as e:
                    self.logger.error(f"Error occurs when writing num to OutputStram: {e}")

            self.repeat_count = 1
            self.pre_value = value

        self.buffered_values[self.num_buffered_values] = value
        self.num_buffered_values += 1

        # if none of values we encountered occurs more MAX_REPEATED_NUM times
        # we'll use bit-packing
        if self.num_buffered_values == TSFileConfig.RLE_MIN_REPEATED_NUM:
            self.write_or_append_bit_packed_run()

    def clear_buffer(self) -> None:
        raise NotImplementedError

    def convert_buffer(self) -> None:
        raise NotImplementedError

    def write_rle_run(self) -> None:
        raise NotImplementedError

    def end_previous_bit_packed_run(self, last_bit_packed_num: int) -> None:
        if not self.is_bit_pack_run:
            return
        bit_pack_header = (self.bit_packed_group_count << 1) | 1
        self.byte_cache.extend([bit_pack_header])
        self.byte_cache.extend([last_bit_packed_num])
        for bytes in self.buffered_values:
            self.byte_cache.extend(bytes)
        self.buffered_values.clear()
        self.is_bit_pack_run = False
        self.bit_packed_group_count = 0

    def write_or_append_bit_packed_run(self) -> None:
        if not self.is_bit_pack_run:
            return
        bitPackedGroupCount = self.bit_packed_group_count + 1
        convertBuffer()
        self.num_buffered_values = 0
        repeatCount = 0
        ++bitPackedGroupCount

    def encode(self, value: Any, out: bytearray) -> None:
        raise TsFileEncodingException("Not implemented")

class TsFileEncodingException(Exception):
    pass