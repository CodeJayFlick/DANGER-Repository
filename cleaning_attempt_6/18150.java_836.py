class IntGorillaEncoder:
    ONE_ITEM_MAX_SIZE = (2 + LEADING_ZERO_BITS_LENGTH_32BIT + MEANINGFUL_XOR_BITS_LENGTH_32BIT + VALUE_BITS_LENGTH_32BIT) // Byte.SIZE + 1

    def __init__(self):
        self.stored_value = 0
        self.first_value_was_written = False

    def get_one_item_max_size(self):
        return self.ONE_ITEM_MAX_SIZE

    def encode(self, value: int, out: bytearray) -> None:
        if not self.first_value_was_written:
            self.write_first(value, out)
            self.first_value_was_written = True
        else:
            self.compress_value(value, out)

    def flush(self, out: bytearray) -> None:
        # ending stream
        self.encode(GORILLA_ENCODING_ENDING_INTEGER, out)

        # flip the byte no matter it is empty or not
        # the empty ending byte is necessary when decoding
        bits_left = 0
        self.flip_byte(out)
        self.reset()

    def reset(self) -> None:
        super().reset()
        self.stored_value = 0

    def write_first(self, value: int, out: bytearray) -> None:
        self.stored_value = value
        self.write_bits(value, VALUE_BITS_LENGTH_32BIT, out)

    def compress_value(self, value: int, out: bytearray) -> None:
        xor = self.stored_value ^ value
        self.stored_value = value

        if xor == 0:
            self.skip_bit(out)
        else:
            self.write_bit(out)

            leading_zeros = bin(xor).count('0')
            trailing_zeros = len(bin(xor)) - leading_zeros - 1
            if leading_zeros >= self.stored_leading_zeros and trailing_zeros >= self.stored_trailing_zeros:
                self.write_existing_leading(xor, out)
            else:
                self.write_new_leading(xor, leading_zeros, trailing_zeros, out)

    def write_existing_leading(self, xor: int, out: bytearray) -> None:
        self.skip_bit(out)

        significant_bits = VALUE_BITS_LENGTH_32BIT - self.stored_leading_zeros - self.stored_trailing_zeros
        self.write_bits(xor >> self.stored_trailing_zeros, significant_bits, out)

    def write_new_leading(self, xor: int, leading_zeros: int, trailing_zeros: int, out: bytearray) -> None:
        self.write_bit(out)

        self.write_bits(leading_zeros, LEADING_ZERO_BITS_LENGTH_32BIT, out)
        self.write_bits((significant_bits := VALUE_BITS_LENGTH_32BIT - 1), MEANINGFUL_XOR_BITS_LENGTH_32BIT, out)
        self.write_bits(xor >> trailing_zeros, significant_bits, out)

        self.stored_leading_zeros = leading_zeros
        self.stored_trailing_zeros = trailing_zeros

    def flip_byte(self, out: bytearray) -> None:
        pass  # This method is not implemented in the original Java code.

GORILLA_ENCODING_ENDING_INTEGER = 0
LEADING_ZERO_BITS_LENGTH_32BIT = 5
MEANINGFUL_XOR_BITS_LENGTH_32BIT = 5
VALUE_BITS_LENGTH_32BIT = 32

if __name__ == "__main__":
    encoder = IntGorillaEncoder()
    out = bytearray()

    # Example usage:
    value1 = 12345
    value2 = 67890
    for i in range(10):
        if i % 2 == 0:
            encoder.encode(value1, out)
        else:
            encoder.encode(value2, out)

    encoder.flush(out)
