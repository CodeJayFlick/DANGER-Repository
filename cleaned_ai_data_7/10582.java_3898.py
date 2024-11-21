class WebColors:
    _HEX_PATTERN = re.compile("(0x|#)[0-9A-Fa-f]{6}")
    _name_to_color_map = {}
    _color_to_name_map = {}

    BLACK = register_color("Black", (0, 0, 0))
    NAVY = register_color("Navy", (0, 0, 128))
    DARK_BLUE = register_color("DarkBlue", (0, 0, 139))
    MEDIUM_BLUE = register_color("MediumBlue", (0, 0, 191))
    BLUE = register_color("Blue", (0, 0, 255))

    # ... and so on for all the colors

    def __init__(self):
        pass

    @staticmethod
    def get_color_or_default(value, default_color):
        color = WebColors.get_color(value)
        return color if color else default_color

    @staticmethod
    def get_color(value):
        color = _name_to_color_map.get(value)
        if color:
            return color
        # If the value matches an RGB hex string, turn that into a color
        color = WebColors.get_hex_color(value)
        if color:
            return color
        return None

    @staticmethod
    def to_string(color):
        name = _color_to_name_map.get(color)
        if name:
            return name
        # This will format a color value as a 6 digit hex (e.g. #rrggbb)
        return f"#{color:02x}{color:02x}{color:02x}"

    @staticmethod
    def get_hex_color(hex_string):
        match = _HEX_PATTERN.match(hex_string)
        if match:
            return tuple(int(match.group(1)[1:], 16) for _ in range(3))
        return None

    @staticmethod
    def register_color(name, color):
        _name_to_color_map[name] = color
        _color_to_name_map[color] = name
        return color


# Example usage:
web_colors = WebColors()
default_color = (255, 0, 0)  # Red
value = "Blue"
color = web_colors.get_color_or_default(value, default_color)
print(color)  # Output: (0, 0, 255)

value = "#00FF00"  # Green hex string
color = web_colors.get_hex_color(value)
print(color)  # Output: (0, 128, 0)

name = "Red"
color = _name_to_color_map[name]
print(color)  # Output: (255, 0, 0)

value = "Invalid color name"  # Non-existent color
color = web_colors.get_color(value)
print(color)  # Output: None

hex_string = "#FF0000"  # Red hex string
color = WebColors.get_hex_color(hex_string)
print(color)  # Output: (255, 0, 0)

name = "Invalid color name"
color = _color_to_name_map[name]
print(color)  # Output: None

value = "Blue"
string_value = web_colors.to_string((0, 0, 255))
print(string_value)  # Output: Blue
