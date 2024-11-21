class ConvertToCharAction:
    ACTION_NAME = "Convert To Char"

    def __init__(self, plugin):
        super().__init__(plugin, self.ACTION_NAME, False)

    def get_menu_name(self, program, scalar, is_data):
        value_string = self.convert_to_string(program, scalar, is_data)
        if not value_string:
            return None
        if scalar.bit_length() > 8:
            return f"Char Sequence: {value_string}"
        return f"Char: {value_string}"

    def get_format_choice(self):
        return "CHAR"

    def convert_to_string(self, program, scalar, is_data):
        bytes = scalar.byte_array_value()
        return "".join([chr(b) for b in bytes])
