class GorillaDecoderV2:
    def __init__(self):
        self.first_value_was_read = False
        self.stored_leading_zeros = 0xFFFFFFFF
        self.stored_trailing_zeros = 0
        self.has_next = True

        self.buffer = 0x00
        self.bits_left = 8

    def reset(self):
        self.first_value_was_read = False
        self.stored_leading_zeros = 0xFFFFFFFF
        self.stored_trailing_zeros = 0
        self.has_next = True

        self.buffer = 0x00
        self.bits_left = 8

    def has_next(self, in_bytes):
        return self.has_next

    def read_bit(self, in_bytes):
        bit = (self.buffer >> (self.bits_left - 1)) & 1 == 1
        self.bits_left -= 1
        if self.bits_left <= 0:
            self.flip_byte(in_bytes)
        return bit

    def flip_byte(self, in_bytes):
        if self.bits_left == 8:
            self.buffer = in_bytes.get()
            self.bits_left = 8

    def read_long(self, bits, in_bytes):
        value = 0
        while bits > 0:
            if bits > self.bits_left or bits == 8:
                byte_data = (self.buffer & ((1 << self.bits_left) - 1))
                value = (value << self.bits_left) + (byte_data & 0xFF)
                bits -= self.bits_left
                self.bits_left = 0
            else:
                byte_data = (self.buffer >> (self.bits_left - bits)) & ((1 << bits) - 1)
                value = (value << bits) + (byte_data & 0xFF)
                self.bits_left -= bits
                bits = 0
            if self.bits_left <= 0:
                self.flip_byte(in_bytes)
        return value

    def read_next_clear_bit(self, max_bits, in_bytes):
        value = 0x00
        for i in range(max_bits):
            value <<= 1
            if self.read_bit(in_bytes):
                value |= 0x01
            else:
                break
        return value
