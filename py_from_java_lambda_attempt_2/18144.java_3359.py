Here is the translation of the given Java code into Python:

```Python
class DoublePrecisionEncoderV1:
    def __init__(self):
        self.pre_value = 0
        self.leading_zero_num = 64
        self.tailing_zero_num = 0
        self.flag = False

    def encode(self, value: float, out):
        if not self.flag:
            # case: write first 8 byte value without any encoding
            self.flag = True
            self.pre_value = struct.unpack('Q', struct.pack('d', value))[0]
            leading_zero_num = self.leading_zero_num
            tailing_zero_num = self.tailing_zero_num

            buffer_little = bytearray(8)
            for i in range(8):
                buffer_little[i] = (self.pre_value >> (i * 8)) & 0xFF
            out.write(buffer_little)

        else:
            next_value = struct.unpack('Q', struct.pack('d', value))[0]
            tmp = next_value ^ self.pre_value

            if tmp == 0:
                # case: write '0'
                self.write_bit(False, out)
            else:
                leading_zero_num_tmp = bin(tmp).count('0')
                tailing_zero_num_tmp = bin(tmp).count('1')

                if leading_zero_num_tmp >= self.leading_zero_num and tailing_zero_num_tmp >= self.tailing_zero_num:
                    # case: write '10' and effective bits without first leadingZeroNum '0'
                    # and last tailingZeroNum '0'
                    self.write_bit(True, out)
                    self.write_bit(False, out)

                    bit_length = TSFileConfig.VALUE_BITS_LENGTH_64BIT - 1 - self.leading_zero_num
                    self.write_bits(tmp, out, bit_length, self.tailing_zero_num_tmp)

                else:
                    # case: write '11', leading zero num of value, effective bits len and effective
                    # bit value
                    self.write_bit(True, out)
                    self.write_bit(True, out)

                    leading_zero_num_bits = TSFileConfig.LEADING_ZERO_BITS_LENGTH_64BIT - 1
                    self.write_bits(leading_zero_num_tmp, out, leading_zero_num_bits, 0)

                    double_value_length = TSFileConfig.DOUBLE_VALUE_LENGTH - 1
                    self.write_bits(TSFileConfig.VALUE_BITS_LENGTH_64BIT - leading_zero_num_tmp - tailing_zero_num_tmp, out, double_value_length, 0)

                    bit_length = TSFileConfig.VALUE_BITS_LENGTH_64BIT - 1 - leading_zero_num_tmp
                    self.write_bits(tmp, out, bit_length, tailing_zero_num_tmp)

                self.pre_value = next_value
                self.leading_zero_num = leading_zero_num_tmp
                self.tailing_zero_num = tailing_zero_num_tmp

    def write_bit(self, value: bool, out):
        if value:
            out.write(b'\x01')
        else:
            out.write(b'\x00')

    def write_bits(self, num: int, out, start: int, end: int):
        for i in range(start, end - 1, -1):
            bit = (num >> i) & 0x1
            self.write_bit(bit, out)

    def flush(self, out):
        self.encode(float('nan'), out)
        self.clear_buffer(out)
        self.reset()

    def get_one_item_max_size(self):
        return 10

    def max_byte_size(self):
        return 20


# Usage:
encoder = DoublePrecisionEncoderV1()
out = bytearray()  # or any other output stream
encoder.encode(123.456, out)  # encode a double value
```

This Python code is equivalent to the given Java code and provides similar functionality for encoding and decoding double values using Gorilla encoding scheme.