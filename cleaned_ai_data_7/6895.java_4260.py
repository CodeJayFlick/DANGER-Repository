class ConvertCharAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Char", 'c')
        self.set_help_location(HelpLocation("DECOMPILER", "ActionConvert"))
        self.set_popup_menu_data(MenuData(["Char"], "Decompile"))

    @property
    def menu_prefix(self):
        return "Char: "

    @staticmethod
    def generate_hex_escape(buffer, value):
        res = hex(value)[2:]
        pad = len(res)
        if pad > 4:
            pad = 8
        elif pad > 2:
            pad = 4
        else:
            pad = 2
        pad -= len(res)
        buffer.append("'\\x")
        for i in range(pad):
            buffer.append('0')
        buffer.append(res.lower())
        buffer.append("')

    def get_equate_name(self, value, size, is_signed, program):
        bytes_ = bytearray(size)
        BigEndianDataConverter().put_value(value, size, bytes_, 0)
        return StringDataInstance.get_char_representation(bytes_.tobytes(), None)

    @staticmethod
    def code_point_needs_escape(codepoint):
        character_class = ord(chr(codepoint))
        if character_class in [32]:  # ASCII space is not escaped
            return False
        elif character_class in [0x20, 0x7f]:
            return True
        else:
            return False

    def get_menu_display(self, value, size, is_signed):
        buffer = StringBuilder()
        if size > 1:
            buffer.append('L')
        if (size == 1 and value >= 127) or self.code_point_needs_escape(value):
            switcher = {
                0: "'\\0'",
                7: "'\\a'",
                8: "'\\b'",
                9: "'\\t'",
                10: "'\\n'",
                11: "'\\v'",
                12: "'\\f'",
                13: "'\\r'",
                '"': "\\\"",
                92: "\\\\",
                '\'': "\\'",
            }
            buffer.append(switcher.get(int(value), lambda: f"\\u{value:04x}"))
        else:
            buffer.append(f"'{chr(value)}'")
        return str(buffer)
