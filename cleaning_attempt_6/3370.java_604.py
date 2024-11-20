class ConflictUtility:
    MAROON = "#990000"
    GREEN = "#009900"
    BLUE = "#000099"
    PURPLE = "#990099"
    DARK_CYAN = "#009999"
    OLIVE = "#999900"
    ORANGE = "#FF9900"
    PINK = "#FF9999"
    YELLOW = "#FFFF00"
    GRAY = "#888888"

    ADDRESS_COLOR = MAROON
    NUMBER_COLOR = MAROON
    EMPHASIZE_COLOR = MAROON
    OFFSET_COLOR = MAROON

    NO_VALUE = "-- No Value --"

    def wrap_as_html(text):
        return "<html><body>" + text + "</body></html>"

    def color_string(rgb_color, text):
        return f"<font color='{rgb_color}'>{text}</font>"

    def color_string_rgb(rgb_color, value):
        return f"<font color='{rgb_color}'>{value}</font>"

    @staticmethod
    def spaces(num):
        buf = ""
        for i in range(num):
            buf += "&nbsp;"
        return buf

    @classmethod
    def add_count(cls, buf, count):
        buf.append(str(count))

    @classmethod
    def add_address(cls, buf, addr):
        if isinstance(addr, int):
            buf.append(str(addr))
        elif hasattr(addr, 'getMinAddress'):
            buf.append(f"{addr.getMinAddress()}-{addr.getMaxAddress()}")

    @staticmethod
    def get_conflict_count(conflict_num, total_conflicts):
        return f"Conflict #{conflict_num} of {total_conflicts}"

    @classmethod
    def get_address_conflict_count(cls, address_num, total_addresses, is_range=False):
        if is_range:
            prefix = "Address range #"
        else:
            prefix = "Address #"
        return f"{prefix}{address_num} of {total_addresses} with conflicts"

    @staticmethod
    def get_truncated_html_string(original_string, trunc_length):
        original_len = len(original_string)
        if original_len > trunc_length:
            truncated_str = original_string[:trunc_length-3] + "..."
        else:
            truncated_str = original_string

        return ConflictUtility.wrap_as_html(ConflictUtility.replace_new_lines(truncated_str))

    @staticmethod
    def replace_new_lines(text):
        buf = ""
        start = 0
        while start < len(text):
            index = text.find('\n', start)
            if index == -1:
                buf += text[start:]
                break
            else:
                buf += text[start:index]
                buf += "<br>"
                start = index + 1

        return buf

    @classmethod
    def get_address_string(cls, address):
        return cls.color_string(ConflictUtility.ADDRESS_COLOR, str(address))

    @classmethod
    def get_number_string(cls, count):
        return cls.color_string(ConflictUtility.NUMBER_COLOR, str(count))
