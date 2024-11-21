Here is the translation of the Java code to Python:
```python
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
```
Note that I had to create `Program` and `Scalar` classes as placeholders, since they are not defined in the original Java code. In a real-world implementation, you would need to define these classes or use existing ones.

Also, I used f-strings for string formatting, which is a Python 3.6+ feature. If you're using an earlier version of Python, you can use regular string concatenation instead.