class LongPacker:
    NUM_OF_LONGS = 8

    def __init__(self, width):
        self.width = width

    def pack8Values(self, values, offset, buf):
        buf_idx = 0
        value_idx = offset
        left_bit = 0

        while value_idx < self.NUM_OF_LONGS + offset:
            buffer = 0
            left_size = 64

            if left_bit > 0:
                buffer |= (values[value_idx] << (64 - left_bit))
                left_size -= left_bit
                left_bit = 0
                value_idx += 1

            while left_size >= self.width and value_idx < self.NUM_OF_LONGS + offset:
                buffer |= (values[value_idx] << (left_size - self.width))
                left_size -= self.width
                value_idx += 1

            if left_size > 0 and value_idx < self.NUM_OF_LONGS + offset:
                buffer |= (values[value_idx] >> (self.width - left_size))
                left_bit = self.width - left_size
                value_idx += 1

            for j in range(8):
                buf[buf_idx] = (buffer >> ((8 - j - 1) * 8)) & 0xFF
                buf_idx += 1
                if buf_idx >= self.width * 8 // 8:
                    return

    def unpack8Values(self, buf, offset, values):
        byte_idx = offset
        value_idx = 0
        left_bits = 8
        total_bits = 0

        while value_idx < 8:
            values[value_idx] = 0
            while total_bits < self.width:
                if self.width - total_bits >= left_bits:
                    values[value_idx] <<= left_bits
                    values[value_idx] |= ((1 << left_bits) - 1) & buf[byte_idx]
                    total_bits += left_bits
                    byte_idx += 1
                    left_bits = 8
                else:
                    t = self.width - total_bits
                    values[value_idx] <<= t
                    values[value_idx] |= ((1 << (left_bits - t)) - 1) & buf[byte_idx]
                    left_bits -= t
                    total_bits += t

            value_idx += 1
            total_bits = 0

    def unpackAllValues(self, buf, length, values):
        idx = 0
        k = 0

        while idx < length:
            tv = [0] * self.NUM_OF_LONGS
            self.unpack8Values(buf, idx, tv)
            for i in range(8):
                values[k + i] = tv[i]
            idx += self.width
            k += 8


# Example usage:

packer = LongPacker(3)

values = [5, 4, 7, 3, 0, 1, 3, 2]

buf = bytearray()

packer.pack8Values(values, 0, buf)

print(buf)
