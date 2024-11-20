Here is the translation of the given Java code into equivalent Python:

```Python
class ArrayDataTypeHTMLRepresentation:
    def __init__(self, array):
        self.array = array
        self.header_content = self.build_header_content()
        self.body_html = self.build_body_html(False)
        self.footer_content = self.build_footer_content()

        original_html_data = self.build_html_text(self.header_content, self.body_html, self.footer_content, False)

        trimmed_body_html = self.build_body_html(True)
        self.truncated_html_data = self.build_html_text(self.header_content, trimmed_body_html, self.footer_content, True)

    def __init__(self, array, header_content=None, body_html=None, footer_content=None):
        if header_content is None:
            header_content = self.build_header_content()
        if body_html is None:
            body_html = self.build_body_html(False)
        if footer_content is None:
            footer_content = self.build_footer_content()

        original_html_data = self.build_html_text(header_content, body_html, footer_content, False)

        trimmed_body_html = self.build_body_html(True)
        self.truncated_html_data = self.build_html_text(header_content, trimmed_body_html, footer_content, True)

    def get_base_data_type(self):
        base_data_type = self.array
        while isinstance(base_data_type, list):
            array = base_data_type
            base_data_type = array[0].get_data_type()
        return base_data_type

    def build_body_html(self, trim=False):
        buffy = StringBuilder()

        base_data_type = self.get_base_data_type()
        if isinstance(base_data_type, BuiltInDataType):
            simple_name = str(type(base_data_type)).split('.')[-1]
            buffy.append(simple_name)
            self.add_data_type_length(base_data_type, buffy)
        else:
            representation = ToolTipUtils().get_html_representation(base_data_type)
            base_html = representation.get_full_html_content_string()
            if trim:
                base_html = representation.get_html_content_string()

            buffy.append(base_html)

            if not base_html.startswith(LENGTH_PREFIX):
                self.add_data_type_length(base_data_type, buffy)

        buffy.append('}')
        return str(buffy)

    def build_header_content(self):
        buffy = StringBuilder()
        buffy.append('/')
        buffy.append('/')
        buffy.append(' ')
        buffy.append(HTMLUtilities().friendly_encode_html(str(self.array).getName()))
        return TextLine(str(buffy))

    def build_footer_content(self):
        len_ = self.array.get_length()
        if not self.array.is_zero_length():
            return TextLine("Size: " + str(len_) + "(reported size is " + str(len_) + ")")
        else:
            return TextLine("Size: 0")

    def build_html_text(self, header, body, info, trim=False):
        buffy = StringBuilder()

        text_line_header = TextLine(str(header))
        if trim:
            text_line_header.set_text(StringUtilities().trim_middle(text_line_header.get_text(), ToolTipUtils().LINE_LENGTH))

        buffy.append(wrap_string_in_color(text_line_header.get_text(), text_line_header.get_text_color()))
        buffy.append('\n')
        text_line_info = TextLine(str(info))
        if trim:
            text_line_info.set_text(StringUtilities().trim_middle(text_line_info.get_text(), ToolTipUtils().LINE_LENGTH))

        buffy.append(wrap_string_in_color(text_line_info.get_text(), text_line_info.get_text_color()))
        buffy.append('\n')
        buffy.append(body)
        return str(buffy)

    def get_html_string(self):
        return '<' + self.truncated_html_data + '>'

    def get_html_content_string(self):
        return self.truncated_html_data

    @staticmethod
    def completely_different_diff(other_representation):
        pass  # This method is not implemented in the given Java code.

    def diff(self, other_representation):
        if self == other_representation:
            return [self, self]
        elif not isinstance(other_representation, ArrayDataTypeHTMLRepresentation):
            return completely_different_diff(other_representation)
        else:
            array = self.array
            other_array = other_representation.array

            header = self.header_content.copy()
            footer = self.footer_content.copy()

            body = self.body_html
            other_body = other_representation.body_html

            if not array.is_equivalent(other_array):
                body = wrap_string_in_color(body, DIFF_COLOR)
                other_body = wrap_string_in_color(other_body, DIFF_COLOR)

            header_diff = DataTypeDiffBuilder().diff_header(self.get_diff_input(header), self.get_diff_input(other_representation.header_content))
            footer_diff = DataTypeDiffBuilder().diff_lines(self.get_diff_input(footer), self.get_diff_input(other_representation.footer_content))

            return [ArrayDataTypeHTMLRepresentation(array, header_diff.left_lines[0], body, footer_diff.left_lines[0]),
                    ArrayDataTypeHTMLRepresentation(other_array, header_diff.right_lines[0], other_body, footer_diff.right_lines[0])]

    @staticmethod
    def wrap_string_in_color(string, color):
        if not color:
            return string

        rgb = HTMLUtilities().to_hex_string(color)
        return "<DIV STYLE='color: " + rgb + ";'>" + string + "</DIV>"
```

Note that this translation is based on the assumption that `BuiltInDataType`, `HTMLUtilities`, and other classes are defined elsewhere in your Python code.