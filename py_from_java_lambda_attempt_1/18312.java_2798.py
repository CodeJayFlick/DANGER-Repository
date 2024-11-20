Here is the translation of the Java code into Python:

```Python
class ReadWriteForEncodingUtils:
    TOO_LONG_BYTE_FORMAT = "tsfile-common BytesUtils: encountered value ({}) that requires more than 4 bytes"

    def __init__(self):
        pass

    @staticmethod
    def get_int_max_bit_width(int_list):
        max_value = 1
        for num in int_list:
            bit_width = 32 - bin(num).count('0')
            max_value = max(max_value, bit_width)
        return max_value

    @staticmethod
    def get_long_max_bit_width(long_list):
        max_value = 1
        for num in long_list:
            bit_width = 64 - bin(num)[2:].count('0')
            max_value = max(max_value, bit_width)
        return max_value

    @staticmethod
    def get_unsigned_var_int(value):
        pre_value = value
        length = 0
        while (value & 0xFFFFFF80) != 0:
            length += 1
            value >>= 7
        length += 1

        result = [0] * length
        i = 0
        while (value & 0xFFFFFF80) != 0:
            result[i] = (value & 0x7F) | 0x80
            value >>= 7
            i += 1
        result[i] = value & 0x7F

        return bytes(result)

    @staticmethod
    def read_unsigned_var_int(stream):
        value = 0
        i = 0
        while stream.read(1) != b'':
            if (value & 0xFFFFFF80) == 0:
                break
            value |= int.from_bytes(stream.read(1), 'big') << i
            i += 7

    @staticmethod
    def read_var_int(stream):
        return ReadWriteForEncodingUtils.read_unsigned_var_int(stream)

    @staticmethod
    def write_unsigned_var_int(value, stream):
        position = 1
        while (value & 0xFFFFFF80) != 0:
            stream.write((value & 0x7F) | 0x80)
            value >>= 7
            position += 1

        if position > 4:
            raise Exception(ReadWriteForEncodingUtils.TOO_LONG_BYTE_FORMAT.format(position))

        stream.write(value & 0x7F)

    @staticmethod
    def write_var_int(value, stream):
        ReadWriteForEncodingUtils.write_unsigned_var_int((value << 1) | (not value), stream)

    @staticmethod
    def var_int_size(value):
        u_value = value << 1 if value < 0 else value
        position = 1

        while (u_value & 0xFFFFFF80) != 0:
            u_value >>= 7
            position += 1

        return position

    @staticmethod
    def u_var_int_size(value):
        position = 1

        while (value & 0xFFFFFF80) != 0:
            value >>= 7
            position += 1

        return position

    @staticmethod
    def write_int_little_endian_padded_on_bit_width(value, stream, bit_width):
        padded_byte_num = (bit_width + 7) // 8
        if padded_byte_num > 4:
            raise Exception(ReadWriteForEncodingUtils.TOO_LONG_BYTE_FORMAT.format(padded_byte_num))

        offset = 0

        while padded_byte_num > 0:
            stream.write((value >> offset) & 0xFF)
            offset += 8
            padded_byte_num -= 1

    @staticmethod
    def read_int_little_endian_padded_on_bit_width(buffer, bit_width):
        padded_byte_num = (bit_width + 7) // 8
        if padded_byte_num > 4:
            raise Exception(ReadWriteForEncodingUtils.TOO_LONG_BYTE_FORMAT.format(padded_byte_num))

        result = 0

        offset = 0

        while padded_byte_num > 0:
            ch = buffer.read(1)
            result |= int.from_bytes(ch, 'big') << offset
            offset += 8
            padded_byte_num -= 1

        return result

    @staticmethod
    def write_long_little_endian_padded_on_bit_width(value, stream, bit_width):
        padded_byte_num = (bit_width + 7) // 8
        if padded_byte_num > 8:
            raise Exception(ReadWriteForEncodingUtils.TOO_LONG_BYTE_FORMAT.format(padded_byte_num))

        for i in range(padded_byte_num):
            ch = value.to_bytes(1, 'big')
            stream.write(ch)
            value >>= 8

    @staticmethod
    def read_long_little_endian_padded_on_bit_width(buffer, bit_width):
        padded_byte_num = (bit_width + 7) // 8
        if padded_byte_num > 8:
            raise Exception(ReadWriteForEncodingUtils.TOO_LONG_BYTE_FORMAT.format(padded_byte_num))

        result = 0

        for i in range(padded_byte_num):
            ch = buffer.read(1)
            result |= int.from_bytes(ch, 'big') << (i * 8)

        return result
```

Please note that Python does not have direct equivalent of Java's `int` and `long`. It has only one type for integers which is called `int`, but it can hold values from -2^63 to 2^63-1. If you need a larger integer, you should use the `decimal` module or some other library that supports arbitrary precision arithmetic.