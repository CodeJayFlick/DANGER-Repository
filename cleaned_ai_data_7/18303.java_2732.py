class BitMap:
    BIT_UTIL = [1, 2, 4, 8, 16, 32, 64, -128]
    UNMARK_BIT_UTIL = [
        0XFE,  # 11111110
        0XFD,  # 11111101
        0XFB,  # 11111011
        0XF7,  # 11110111
        0XEF,  # 11101111
        0XDF,  # 11011111
        0XBF,  # 10111111
        0X7F   # 01111111
    ]

    def __init__(self, size):
        self.size = size
        self.bits = [0] * ((size + 7) // 8)

    def get_bits(self):
        return self.bits

    def get_size(self):
        return self.size

    def is_marked(self, position):
        byte_index = position // 8
        bit_index = position % 8
        return (self.bits[byte_index] & (1 << bit_index)) != 0

    def mark_all(self):
        for i in range(len(self.bits)):
            self.bits[i] = 0xFF

    def mark(self, position):
        byte_index = position // 8
        bit_index = position % 8
        self.bits[byte_index] |= (1 << bit_index)

    def reset(self):
        for i in range(len(self.bits)):
            self.bits[i] = 0

    def unmark(self, position):
        byte_index = position // 8
        bit_index = position % 8
        self.bits[byte_index] &= ~(1 << bit_index)

    def is_all_unmarked(self):
        for i in range(len(self.bits)):
            if self.bits[i] != 0:
                return False
        return True

    def is_all_marked(self):
        for i in range(len(self.bits)):
            if self.bits[i] != 0xFF:
                return False
        return True

    def __str__(self):
        res = ''
        for i in range(self.size):
            res += '1' if self.is_marked(i) else '0'
        return res

    def clone(self):
        bits_clone = [x for x in self.bits]
        return BitMap(self.size, bits_clone)

    @staticmethod
    def copy_of_range(src, src_pos, dest, dest_pos, length):
        if src_pos + length > len(src.get_bits()):
            raise IndexError("src position out of range")
        elif dest_pos + length > len(dest.get_bits()):
            raise IndexError("dest position out of range")

        for i in range(length):
            if src.is_marked(src_pos + i):
                dest.mark(dest_pos + i)
            else:
                dest.unmark(dest_pos + i)

# Example usage
bitmap = BitMap(1000)  # Create a bitmap with size 1000
print(bitmap.get_size())  # Print the size of the bitmap

# Mark all bits in the bitmap
bitmap.mark_all()
print(bitmap.is_all_marked())

# Unmark some bits
for i in range(500):
    if i % 2 == 1:
        bitmap.unmark(i)
print(bitmap.is_all_unmarked())
