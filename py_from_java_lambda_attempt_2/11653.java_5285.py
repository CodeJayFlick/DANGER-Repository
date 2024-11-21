Here is the translation of the given Java code into Python:

```Python
import struct

class Utils:
    endl = '\n'

    uintbmasks = [0, 255, 65535, 16777215, 4294967295, 18446744073709551615,
                  9223372036854775807, 18446744073709551199]

    @staticmethod
    def convert_to_signed_value(val, byte_size):
        signbit = (byte_size * 8) - 1
        if val.bit_length() < signbit:
            return val
        else:
            return val - (2 ** (signbit + 1))

    @staticmethod
    def convert_to_unsigned_value(val, byte_size):
        if val.signum() >= 0:
            return val
        mask = (2 ** (byte_size * 8)) - 1
        return val & mask

    @staticmethod
    def calc_mask(size):
        return Utils.uintbmasks[min(7, size)]

    @staticmethod
    def calc_bigmask(size):
        return (2 ** size * 8) - 1

    @staticmethod
    def signbit_negative(val, size):
        if val & (0x80 << ((size - 1) * 8)):
            return True
        else:
            return False

    @staticmethod
    def uintb_negate(in_val, size):
        return ~in_val & Utils.calc_mask(size)

    @staticmethod
    def sign_extend(in_val, size_in, size_out):
        in_val &= Utils.calc_mask(size_in)
        if size_in >= size_out:
            return in_val
        else:
            mask = (2 ** size_out * 8) - 1
            tmp = mask << ((size_in - 1) * 8)
            tmp <<= 1 & mask
            in_val |= tmp
            return in_val

    @staticmethod
    def zzz_sign_extend(val, bit):
        if val >> (bit - 1) & 0x01:
            val |= (2 ** bit - 1) << ((bit - 1) * 8)
        else:
            val &= ~(2 ** bit - 1) << ((bit - 1) * 8)
        return val

    @staticmethod
    def zzz_zero_extend(val, bit):
        mask = (2 ** bit - 1) << ((bit - 1) * 8)
        mask <<= 1 & mask
        return val & ~mask

    @staticmethod
    def byte_swap(val, size):
        res = 0
        for i in range(size):
            res <<= 8 | (val & 0xFF)
            val >>= 8
        return res

    @staticmethod
    def bytes_to_long(byte_buf, size, big_endian):
        value = 0
        for i in range(size):
            value <<= 8 | byte_buf[i]
        if not big_endian:
            value = Utils.byte_swap(value, size)
        return value

    @staticmethod
    def long_to_bytes(val, size, big_endian):
        bytes = [0] * size
        for i in range(size):
            bytes[size - i - 1] = val & 0xFF
            val >>= 8
        if not big_endian:
            val = Utils.byte_swap(val, size)
        return bytes

    @staticmethod
    def bytes_to_big_integer(byte_buf, size, big_endian, signed):
        if big_endian:
            converter = BigEndianDataConverter()
        else:
            converter = LittleEndianDataConverter()
        return converter.get_biginteger(byte_buf, size, signed)

    @staticmethod
    def big_integer_to_bytes(val, size, big_endian):
        if big_endian:
            converter = BigEndianDataConverter()
        else:
            converter = LittleEndianDataConverter()
        return converter.get_bytes(val, size)
```

This Python code is a direct translation of the given Java code.