class BitGroup:
    def __init__(self, value):
        self.values = set([value])
        self.mask = value

    def intersects(self, bit_group):
        return (bit_group.mask & self.mask) != 0

    def merge(self, bit_group):
        self.values.update(bit_group.values)
        self.mask |= bit_group.mask

    def __str__(self):
        buf = "BitGroup - Mask: {0:x} values:".format(self.mask)
        for value in self.values:
            buf += "{0}, ".format(value)
        return buf[:-2]  # remove the extra comma and space at the end

    @property
    def mask(self):
        return self._mask

    @mask.setter
    def mask(self, value):
        self._mask = value

    @property
    def values(self):
        return self._values

    @values.setter
    def values(self, value_set):
        if not isinstance(value_set, set):
            raise TypeError("Values must be a set of Longs")
        self._values = value_set


# Example usage:
bg1 = BitGroup(0x5)
print(bg1)

bg2 = BitGroup(0x8)
print(bg2)

bg1.merge(bg2)
print(bg1)

print(bg1.intersects(BitGroup(0x4)))
