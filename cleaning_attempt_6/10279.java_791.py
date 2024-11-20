class UnsignedDataUtils:
    def __init__(self):
        pass

    @staticmethod
    def comp(type, i, j):
        if isinstance(i, int) or isinstance(j, int):
            return comp_long(type, i, j)
        elif isinstance(i, bytes) and isinstance(j, bytes):
            return comp_bytes(type, i, j)

    @staticmethod
    def comp_long(type, i, j):
        is_hi_bit_set_i = i < 0
        is_hi_bit_set_j = j < 0

        if is_hi_bit_set_i == is_hi_bit_set_j:
            # same sign...
            return {
                0: (i < j),
                1: (i <= j),
                2: (i > j),
                3: (i >= j)
            }[type]
        elif is_hi_bit_set_i:
            return False
        else:
            return True

    @staticmethod
    def comp_bytes(type, i, j):
        if isinstance(i, bytes) and isinstance(j, bytes):
            # handle byte comparison here...
            pass

    @staticmethod
    def unsigned_less_than(i, j):
        return UnsignedDataUtils.comp(UnsignedDataUtils.LESS_THAN, i, j)

    @staticmethod
    def unsigned_less_than_or_equal(i, j):
        return UnsignedDataUtils.comp(UnsignedDataUtils.LESS_THAN_OR_EQUAL, i, j)

    @staticmethod
    def unsigned_greater_than(i, j):
        return UnsignedDataUtils.comp(UnsignedDataUtils.GREATER_THAN, i, j)

    @staticmethod
    def unsigned_greater_than_or_equal(i, j):
        return UnsignedDataUtils.comp(UnsignedDataUtils.GREATER_THAN_OR_EQUAL, i, j)


UnsignedDataUtils.LESS_THAN = 0
UnsignedDataUtils.LESS_THAN_OR_EQUAL = 1
UnsignedDataUtils.GREATER_THAN = 2
UnsignedDataUtils.GREATER_THAN_OR_EQUAL = 3

# Example usage:
print(UnsignedDataUtils.unsigned_less_than(5, 250))
