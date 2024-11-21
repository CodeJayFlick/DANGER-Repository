Here is the translation of the Java code to Python:
```python
import io
from typing import List

class IntRleEncoder:
    def __init__(self):
        self.values = []
        self.packer = None
        self.buffered_values = [0] * TSFileConfig.RLE_MIN_REPEATED_NUM
        self.pre_value = 0
        self.repeat_count = 0
        self.num_buffered_values = 0

    def encode(self, value: int, out: io.BytesIO):
        self.values.append(value)

    def flush(self, out: io.BytesIO) -> None:
        if not self.values:
            return
        bit_width = ReadWriteForEncodingUtils.get_int_max_bit_width(self.values)
        self.packer = IntPacker(bit_width)
        for value in self.values:
            self.encode_value(value)
        super().flush(out)

    def reset(self):
        super().reset()
        self.pre_value = 0

    def write_rle_run(self) -> None:
        end_previous_bit_packed_run(TSFileConfig.RLE_MIN_REPEATED_NUM)
        ReadWriteForEncodingUtils.write_unsigned_var_int(
            (self.repeat_count << 1), byte_cache
        )
        ReadWriteForEncodingUtils.write_int_little_endian_padded_on_bit_width(
            self.pre_value, byte_cache, bit_width
        )
        self.repeat_count = 0
        self.num_buffered_values = 0

    def clear_buffer(self):
        for i in range(self.num_buffered_values, TSFileConfig.RLE_MIN_REPEATED_NUM):
            self.buffered_values[i] = 0

    def convert_buffer(self) -> None:
        bytes_ = bytearray(bit_width)
        tmp_buffer = [int(x) for x in self.buffered_values]
        self.packer.pack8values(tmp_buffer, 0, bytes_)
        # we'll not write bit-packing group to OutputStream immediately
        # we buffer them in list
        bytes_buffer.append(bytes_)

    def get_one_item_max_size(self):
        return 45

    def max_byte_size(self) -> int:
        if self.values is None:
            return 0
        group_num = (len(self.values) // 8 + 1) // 63 + 1
        return len(self.values) * 4 + group_num * 5 + 8
```
Note that I had to make some assumptions about the `TSFileConfig` class and its constants, as well as the `ReadWriteForEncodingUtils` class. You may need to modify this code further depending on how these classes are implemented in your Python environment.

Also, keep in mind that this is a direct translation of the Java code to Python, without any optimization or refactoring for Python-specific considerations (e.g., using NumPy arrays instead of lists).