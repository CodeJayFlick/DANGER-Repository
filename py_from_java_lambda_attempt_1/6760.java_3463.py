Here is the translation of the given Java code into Python:

```Python
class OctalFormatModel:
    def __init__(self):
        self.symbol_size = 3

    def get_name(self):
        return "Octal"

    def get_unit_byte_size(self):
        return 1

    def get_byte_offset(self, block, position):
        return 0

    def get_column_position(self, block, byte_offset):
        return 0

    def get_data_unit_symbol_size(self):
        return self.symbol_size

    def data_representation(self, block, index):
        b = block.getByte(index)
        i = int.from_bytes([b], 'big')
        str_val = oct(i)[2:]
        
        if len(str_val) > self.symbol_size:
            str_val = str_val[-self.symbol_size:]

        return pad(str_val)

    def is_editable(self):
        return True

    def replace_value(self, block, index, char_position, c):
        if 0 <= char_position < 3 and GOOD_CHARS.find(c) != -1:
            b = block.getByte(index)
            i = int.from_bytes([b], 'big')
            
            if char_position == 0:
                i &= 0x3f
                cb = ord('7') << 6 | c
                b += bytes([cb])
            elif char_position == 1:
                i &= 0xc7
                cb = ord(c) << 3 | (b & 0xf)
                b += bytes([cb])
            else:
                i &= 0xf8
                b += bytes([c])

            block.setByte(index, int.to_bytes(i, 'big', False)[0])
            return True

        return False

    def get_group_size(self):
        return 1

    def set_group_size(self, group_size):
        raise Exception("groups are not supported")

    def get_unit_delimiter_size(self):
        return 1

    def validate_bytes_per_line(self, bytes_per_line):
        return True


def pad(value):
    len_val = OctalFormatModel.symbol_size - len(value)
    
    for _ in range(len_val):
        value = "0" + value
    
    return value


class HelpLocation:
    def __init__(self, plugin_name, help_topic):
        self.plugin_name = plugin_name
        self.help_topic = help_topic

    def get_plugin_name(self):
        return self.plugin_name

    def get_help_topic(self):
        return self.help_topic
```

Note: The `ByteBlock` class is not present in the given Java code. In Python, we can't directly translate it as there's no equivalent concept like a byte block.