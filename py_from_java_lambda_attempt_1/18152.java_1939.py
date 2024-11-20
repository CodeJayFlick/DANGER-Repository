Here is the translation of the Java code into Python:

```Python
class LongGorillaEncoder:
    ONE_ITEM_MAX_SIZE = (2 + 64 + 64) // 8 + 1

    def __init__(self):
        self.stored_value = 0
        self.first_value_was_written = False
        self.bits_left = 0

    def get_one_item_max_size(self):
        return self.ONE_ITEM_MAX_SIZE

    def encode(self, value: int, out: bytearray) -> None:
        if not self.first_value_was_written:
            self.write_first(value, out)
            self.first_value_was_written = True
        else:
            self.compress_value(value, out)

    def flush(self, out: bytearray) -> None:
        self.encode(GORILLA_ENCODING_ENDING_LONG, out)
        self.flip_byte(out)
        self.reset()

    def reset(self):
        super().reset()
        self.stored_value = 0

    def write_first(self, value: int, out: bytearray) -> None:
        self.stored_value = value
        self.write_bits(value, VALUE_BITS_LENGTH_64BIT, out)

    def compress_value(self, value: int, out: bytearray) -> None:
        xor = self.stored_value ^ value
        self.stored_value = value

        if xor == 0:
            self.skip_bit(out)
        else:
            self.write_bit(out)
            leading_zeros = bin(xor).count('0')
            trailing_zeros = len(bin(xor)) - len(bin(xor)).lstrip('0') - 1
            if leading_zeros >= stored_leading_zeros and trailing_zeros >= stored_trailing_zeros:
                self.write_existing_leading(xor, out)
            else:
                self.write_new_leading(xor, leading_zeros, trailing_zeros, out)

    def write_existing_leading(self, xor: int, out: bytearray) -> None:
        self.skip_bit(out)
        significant_bits = VALUE_BITS_LENGTH_64BIT - stored_leading_zeros - stored_trailing_zeros
        self.write_bits(xor >> stored_trailing_zeros, significant_bits, out)

    def write_new_leading(self, xor: int, leading_zeros: int, trailing_zeros: int, out: bytearray) -> None:
        self.write_bit(out)
        self.write_bits(leading_zeros, LEADING_ZERO_BITS_LENGTH_64BIT, out)
        self.write_bits((significant_bits - 1), MEANINGFUL_XOR_BITS_LENGTH_64BIT, out)
        self.write_bits(xor >> trailing_zeros, significant_bits, out)

    def write_bit(self, out: bytearray) -> None:
        pass

    def skip_bit(self, out: bytearray) -> None:
        pass

    def flip_byte(self, out: bytearray) -> None:
        pass
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.