class ConvertToUnsignedDecimalAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Convert To Unsigned Decimal", False)

    def get_menu_name(self, program, scalar, is_data):
        s = scalar
        if s.is_signed():
            s = Scalar(s.bit_length(), s.get_unsigned_value(), False)
        return f"Unsigned Decimal: {s.to_string(10, False, False, '', '')}"

    def convert_to_string(self, program, scalar, is_data):
        return str(scalar.get_unsigned_value())

    def get_format_choice(self):
        return FormatSettingsDefinition.DECIMAL
