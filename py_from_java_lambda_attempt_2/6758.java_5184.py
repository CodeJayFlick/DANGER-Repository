Here is the translation of the given Java code into Python:

```Python
class HexIntegerFormatModel:
    def __init__(self):
        self.symbol_size = 8

    def get_name(self):
        return "HexInteger"

    def get_unit_byte_size(self):
        return 4

    def get_byte_offset(self, block, position):
        o = position // 2
        if block.is_big_endian():
            return o
        else:
            return 3 - o

    def get_column_position(self, block, byte_offset):
        if byte_offset > 3:
            raise ValueError("invalid byteOffset: " + str(byte_offset))
        if block.is_big_endian():
            return byte_offset * 2
        else:
            return (3 - byte_offset) * 2

    def get_data_unit_symbol_size(self):
        return self.symbol_size

    def data_representation(self, block, index):
        try:
            i = int.from_bytes(block.get_bytes(index), 'big' if block.is_big_endian() else 'little')
            str_val = hex(i)[2:].zfill(8)
            return pad(str_val)

        except Exception as e:
            print("Error: " + str(e))
            return ""

    def is_editable(self):
        return True

    def replace_value(self, block, index, char_position, c):
        if char_position < 0 or char_position > self.symbol_size - 1:
            return False
        try:
            int.from_bytes(c.encode(), 'big' if block.is_big_endian() else 'little')
        except ValueError as e:
            print("Error: " + str(e))
            return False

        byte_offset = get_byte_offset(block, char_position)
        save_index = index
        index += bytes_to_int(byte_offset)

        try:
            b = int.from_bytes(c.encode(), 'big' if block.is_big_endian() else 'little')
            newb = (block.get_byte(index) & 0x0f) | ((b >> 4) << 4)
            if not block.is_big_endian():
                newb = (newb & 0xf0) | ((block.get_byte(save_index)) & 0x0f)

            b = int.from_bytes(block.get_bytes(index), 'big' if block.is_big_endian() else 'little')
            block.set_bytes(save_index, bytes([int((b >> i * 8) & 0xff) for i in range(4)]))
        except Exception as e:
            print("Error: " + str(e))

    def get_group_size(self):
        return 1

    def set_group_size(self, group_size):
        raise ValueError("groups are not supported")

    def get_unit_delimiter_size(self):
        return 1

    def validate_bytes_per_line(self, bytes_per_line):
        return bytes_per_line % 4 == 0


def pad(value):
    len = self.symbol_size - len(value)
    for i in range(len):
        value = "0" + value
    return value


def adjust_byte(b, newb, char_position):
    if char_position % 2 == 0:
        b &= 0x0f
        newb <<= 4
    else:
        b &= 0xf0

    b += newb
    return b


def bytes_to_int(byte_offset):
    return int.from_bytes([block.get_byte(index) for index in range(4)], 'big' if block.is_big_endian() else 'little')


class ByteBlock:
    def __init__(self, is_big_endian=False):
        self.is_big_endian = is_big_endian

    def get_bytes(self, offset):
        # implement this method
        pass

    def set_bytes(self, offset, value):
        # implement this method
        pass


def main():
    block = ByteBlock()
    model = HexIntegerFormatModel()

    print(model.get_name())
    print(model.get_unit_byte_size())

    try:
        print(model.data_representation(block, 0))
    except Exception as e:
        print("Error: " + str(e))

    print(model.is_editable())

    try:
        model.replace_value(block, 0, 0, 'a')
    except Exception as e:
        print("Error: " + str(e))


if __name__ == "__main__":
    main()
```

Please note that the `ByteBlock` class is not implemented in this code. You would need to implement it according to your specific requirements.