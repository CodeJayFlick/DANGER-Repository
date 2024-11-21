class ConvertToUnsignedHexAction:
    ACTION_NAME = "Convert To Unsigned Hex"

    def __init__(self):
        pass  # equivalent to public ConvertToUnsignedHexAction(EquatePlugin plugin)

    def get_menu_name(self, program: Program, scalar: Scalar, is_data: bool) -> str:
        return f"Unsigned Hex: {convert_to_string(program, scalar, is_data)}"

    def convert_to_string(self, program: Program, scalar: Scalar, is_data: bool) -> str:
        value_str = hex(scalar.get_unsigned_value()).upper()
        if is_data:
            # Data relies on data format settings which uses "h" suffix
            return f"{value_str}h"
        else:
            # Instructions rely on equate which uses 0x prefix (consistent with default scalar formatting)
            return f"0x{value_str}"

    def get_format_choice(self) -> int:
        return FormatSettingsDefinition.HEX

class Program: pass
class Scalar: pass
