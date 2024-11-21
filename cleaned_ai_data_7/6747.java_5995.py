class BinaryFormatModel:
    def __init__(self):
        self.symbol_size = 8

    def get_name(self):
        return "Binary"

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
        str_val = bin(i)[2:]
        
        if len(str_val) > self.symbol_size:
            str_val = str_val[-self.symbol_size:]

        return pad(str_val)

    def is_editable(self):
        return True

    def replace_value(self, block, index, char_position, c):
        if 0 <= char_position < 8 and GOOD_CHARS.find(c) != -1:
            b = block.getByte(index)
            mask = (1 << (7 - char_position))
            
            b &= ~mask
            if int.from_bytes([c], 'big'):
                b |= mask
            
            block.setByte(index, bytes([b]))
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
    len_val = BinaryFormatModel.symbol_size - len(value)
    
    for _ in range(len_val):
        value = "0" + value
    
    return value


class HelpLocation:
    def __init__(self, plugin_name, topic_name):
        self.plugin_name = plugin_name
        self.topic_name = topic_name

    def get_help_location(self):
        return f"{self.plugin_name}.{self.topic_name}"


# Example usage:

binary_format_model = BinaryFormatModel()
block = "your byte block"
index = 0
char_position = 3
c = '1'

print(binary_format_model.data_representation(block, index))
print(binary_format_model.replace_value(block, index, char_position, c))

help_location = HelpLocation("ByteViewerPlugin", "Binary")
print(help_location.get_help_location())
