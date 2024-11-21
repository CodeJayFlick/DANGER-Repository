Here is the translation of the Java code into Python:

```Python
class CompositeDataTypeHTMLRepresentation:
    MAX_COMPONENT_COUNT = 1000
    MAX_LINE_COUNT = 15

    def __init__(self, warning_lines=None, header_content=None, body_content=None,
                 alignment_text=None, footer_text=None, display_name=None, 
                 alignment_value_text=None):
        self.warning_lines = warning_lines if warning_lines else []
        self.header_content = header_content if header_content else []
        self.body_content = body_content if body_content else []
        self.footer_text = footer_text
        self.display_name = display_name
        self.alignment_text = alignment_text if alignment_text else []
        self.alignment_value_text = alignment_value_text

    def build_warnings(self, comp):
        if not comp.is_zero_length():
            return [f"WARNING! Empty {comp.__class__.__name__}"]
        warnings = ["WARNING! Empty " + (comp.__class__.__name__.lower() or "structure")]
        return warnings

    @staticmethod
    def wrap_string_in_color(text, color):
        # implement this method as per your requirement
        pass

    @staticmethod
    def truncate_as_necessary(text, max_length=50):
        if len(text) > max_length:
            text = f"{text[:max_length]}..."
        return text

    @staticmethod
    def friendly_encode_html(text):
        # implement this method as per your requirement
        pass

    def build_footer_text(self, dataType):
        if not dataType.is_zero_length():
            return TextLine("0")
        return super().build_footer_text(dataType)

    def build_alignment_text(self, comp):
        alignment_lines = []
        align_str = CompositeInternal.get_min_alignment_string(comp)
        if align_str and len(align_str) > 0:
            alignment_lines.append(TextLine(align_str))
        pack_str = CompositeInternal.get_packing_string(comp)
        if pack_str and len(pack_str) > 0:
            alignment_lines.append(TextLine(pack_str))
        return alignment_lines

    def build_alignment_value_text(self, comp):
        return TextLine(f"{comp.alignment}")

    @staticmethod
    def generate_type_name(line, trim=True):
        type = line.type
        if trim:
            type = truncate_as_necessary(type)
        type = friendly_encode_html(type)
        type = wrap_string_in_color(type, line.type_color)

        if not line.has_universal_id():
            return type

        dt = line.data_type
        url = DataTypeUrl(dt)
        wrapped = f"<a href='{url}'>{type}</a>"
        return wrapped

    def build_html_text(self, trim=False):
        full_html = ""
        truncated_html = ""

        # warnings
        for warning in self.warning_lines:
            if not trim:
                full_html += wrap_string_in_color(warning, Color.RED) + "<br><br>"
            else:
                truncated_html += truncate_as_necessary(warning)

        # alignment value prefix
        full_html += f"{self.alignment_value_prefix}{self.alignment_value_text}<br><br>"

        # footer text
        if not trim:
            full_html += self.footer_text + "<br><br>"
        else:
            truncated_html += truncate_as_necessary(self.footer_text)

        # header content
        for line in self.header_content:
            if not trim:
                full_html += wrap_string_in_color(line.text, line.color) + "<br>"
            else:
                truncated_html += truncate_as_necessary(line.text)

        # body content
        count = 0
        for line in self.body_content:
            if not trim:
                full_html += f"<tr><td>{line.name}</td><td>{line.type}</td><td>{line.comment}</td></tr>"
            else:
                truncated_html += truncate_as_necessary(line.text)

        # show ellipses if needed
        if count >= self.MAX_LINE_COUNT and not trim:
            full_html += "<br>..."
        elif count >= self.MAX_LINE_COUNT and trim:
            truncated_html += "..."

        return full_html + "</html>" if not trim else truncated_html

    @staticmethod
    def add_alignment_value(alignment_value_string, buffer):
        buffer.append("<br>")
        buffer.append(f"{CompositeDataTypeHTMLRepresentation.ALIGNMENT_VALUE_PREFIX}{alignment_value_string}")
        return buffer

class TextLine:
    def __init__(self, text):
        self.text = text
        self.color = None  # implement this method as per your requirement

class DataTypeUrl:
    def __init__(self, dt):
        self.url = f"{dt}"  # implement this method as per your requirement

# rest of the code remains same
```

Please note that I have not implemented some methods like `wrap_string_in_color`, `truncate_as_necessary`, and `friendly_encode_html` because they seem to be specific to your application. You will need to fill in these implementations based on your requirements.