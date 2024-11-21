Here is the equivalent Python code:

```Python
class BitFieldDataTypeHTMLRepresentation:
    def __init__(self, bit_field_dt):
        super().__init__(build_html_text(bit_field_dt))

    @staticmethod
    def build_html_text(bit_field_dt):
        buffer = StringBuilder()

        base_data_type = bit_field_dt.get_base_data_type()
        representation = ToolTipUtils().get_html_representation(base_data_type)
        base_html = representation.get_html_content_string()
        buffer.append(base_html)

        if LENGTH_PREFIX not in base_html:
            length_string = get_data_type_length_string(bit_field_dt)
            buffer.append(LENGTH_PREFIX + length_string)

        description = bit_field_dt.get_description()

        if not StringUtils().is_blank(description):
            description = bit_field_dt.get_display_name()
        else:
            description = HTMLUtilities().friendly_encode_html(description)
        buffer.append(description)

        buffer.append('\n\n')
        buffer.append('Bitfield Base Data Type: \n')

        buffer.append(INDENT_OPEN + base_html + INDENT_CLOSE)

        return str(buffer)

    def diff(self, other_representation):
        raise AssertException("Bitfield types are not diffable at this time")

class StringBuilder:
    def __init__(self):
        self.buffer = ''

    def append(self, text):
        self.buffer += text

    def toString(self):
        return self.buffer
```

Note that Python does not have a direct equivalent to Java's `StringBuilder` class. Instead, you can use the built-in string concatenation operator (`+`) or create your own implementation of a mutable string buffer.

Also note that this code assumes that there are separate functions for getting the base data type and building the length string from the bit field data type. These functions were not provided in the original Java code, so I left them as placeholders (`get_base_data_type` and `get_data_type_length_string`).