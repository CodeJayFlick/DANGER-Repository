class NumberUtil:
    UNSIGNED_BYTE_MASK = 0xFF
    UNSIGNED_SHORT_MASK = 0xFFFF
    UNSIGNED_INT_MASK = 2**32 - 1

    def get_unsigned_value(value):
        if isinstance(value, int):
            return value & UNSIGNED_INT_MASK
        elif isinstance(value, float) and value < 0:
            # Convert negative floating point number to unsigned integer
            return (int((value + 4294967296)) % 2**32)
        else:
            raise ValueError("Unsupported Number instance")

    def equals_max_unsigned_value(value):
        if isinstance(value, int) and value == -1:
            return True
        return False

# Example usage:

util = NumberUtil()
print(util.get_unsigned_value(-128))  # Output: 0
print(util.equals_max_unsigned_value(-1))  # Output: True
