Here is the translation of the Java code into Python:

```Python
class AsciiFormatModel:
    def __init__(self):
        self.symbol_size = 1

    def get_name(self):
        return "Ascii"

    def get_unit_byte_size(self):
        return 1

    def get_byte_offset(self, block, position):
        return 0

    def get_column_position(self, block, byte_offset):
        return 0

    def get_data_unit_symbol_size(self):
        return self.symbol_size

    def get_data_representation(self, block, index):
        try:
            b = block.getByte(index)
            if b < 0x20 or b == 0x7f:
                return "."
            else:
                char_array = [chr(b)]
                return "".join(char_array)
        except Exception as e:
            print(f"Error: {e}")

    def is_editable(self):
        return True

    def replace_value(self, block, index, position, c):
        if position != 0:
            return False
        try:
            cb = bytes([c]).decode("utf-8")
            block.setByte(index, int.from_bytes(cb.encode(), "big"))
            return True
        except Exception as e:
            print(f"Error: {e}")

    def get_group_size(self):
        raise ValueError("groups are not supported")

    def set_group_size(self, group_size):
        raise ValueError("groups are not supported")

    def get_unit_delimiter_size(self):
        return 0

    def validate_bytes_per_line(self, bytes_per_line):
        return True

    def get_help_location(self):
        return HelpLocation("ByteViewerPlugin", "Ascii")

    def dispose(self):
        pass

    def supports_provider(self, provider):
        return True


class HelpLocation:
    def __init__(self, plugin_name, help_topic):
        self.plugin_name = plugin_name
        self.help_topic = help_topic
```

Please note that Python does not have direct equivalent of Java's `ByteBlock` and other classes. I've replaced them with Pythonic way to handle bytes (using `bytes()` function) and exceptions handling using try-except blocks.