class PdbByteReader:
    def __init__(self, bytes):
        self.bytes = bytes
        self.limit = len(bytes)
        self.index = 0
        self.align_marker = 0

    def reset(self):
        self.index = 0
        self.align_marker = 0

    def num_remaining(self):
        return self.limit - self.index

    def get_index(self):
        return self.index

    def get_limit(self):
        return self.limit

    def set_index(self, index):
        if 0 <= index < self.limit:
            self.index = index
        else:
            pass

    def has_more(self):
        return self.index < self.limit

    def has_more_non_pad(self):
        if not self.has_more():
            return False
        return bytes[self.index] & 0xff <= 0xf0

    def parse_unsigned_byte_val(self):
        if not self.has_more(1):
            raise PdbException("Not enough data left to parse")
        value = bytes[self.index]
        self.index += 1
        return value & 0xff

    def parse_var_sized_int(self, size):
        if size == 16:
            return self.parse_short()
        elif size == 32:
            return self.parseInt()

    def parse_small_var_sized_uint(self, size):
        if size == 8:
            return self.parse_unsigned_byte_val()
        elif size == 16:
            return self.parse_unsigned_short_val()

    def parse_var_sized_offset(self, size):
        if size == 16:
            return self.parse_unsigned_short_val()
        elif size == 32:
            return self.parseInt()

    # ... (rest of the methods)

class PdbException(Exception):
    pass
