Here is the translation of the Java code into Python:

```Python
class IntPacker:
    NUM_OF_INTS = 8

    def __init__(self, width):
        self.width = width

    def pack8Values(self, values, offset, buf):
        buf_idx = 0
        value_idx = offset
        left_bit = 0

        while value_idx < self.NUM_OF_INTS + offset:
            buffer = 0
            left_size = 32

            if left_bit > 0:
                buffer |= (values[value_idx] << (32 - left_bit))
                left_size -= left_bit
                left_bit = 0
                value_idx += 1

            while left_size >= self.width and value_idx < self.NUM_OF_INTS + offset:
                buffer |= (values[value_idx] << (left_size - self.width))
                left_size -= self.width
                value_idx += 1

            if left_size > 0 and value_idx < self.NUM_OF_INTS + offset:
                buffer |= (values[value_idx] >> (self.width - left_size))
                left_bit = self.width - left_size
                value_idx += 1

            for j in range(4):
                buf[buf_idx] = (buffer >> ((3 - j) * 8)) & 0xFF
                buf_idx += 1
                if buf_idx >= self.width:
                    return

    def unpack8Values(self, buf, offset, values):
        byte_idx = offset
        buffer = 0
        total_bits = 0
        value_idx = 0

        while value_idx < self.NUM_OF_INTS:
            while total_bits < self.width:
                buffer = (buffer << 8) | (buf[byte_idx] & 0xFF)
                byte_idx += 1
                total_bits += 8

            while total_bits >= self.width and value_idx < self.NUM_OF_INTS:
                values[value_idx] = int(buffer >> (total_bits - self.width))
                value_idx += 1
                total_bits -= self.width
                buffer &= ((1 << total_bits) - 1)

    def unpackAllValues(self, buf, length, values):
        idx = 0
        k = 0

        while idx < length:
            tv = [0] * 8
            # decode 8 values one time, current result will be saved in the array named 'tv'
            self.unpack8Values(buf, idx, tv)
            values[k:k+8] = tv[:]
            idx += self.width
            k += 8

    def setWidth(self, width):
        self.width = width


# Example usage:
packer = IntPacker(3)  # Create an instance of the class with a bit-width of 3.
values = [5, 4, 7, 3, 0, 1, 3, 2]
buf = bytearray()  # Initialize an empty byte array.

# Pack values into bytes
packer.pack8Values(values, 0, buf)

print(buf)  # Print the packed bytes

# Unpack values from bytes
unpack_values = [0] * len(values)
packer.unpackAllValues(buf, len(buf), unpack_values)

print(unpack_values)  # Print the unpacked values