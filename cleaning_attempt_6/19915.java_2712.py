class SkriptChatCode:
    def __init__(self):
        self.has_param = False
        self.color_code = None
        self.lang_name = None
        self.color_char = None

    @property
    def has_param(self):
        return self._has_param

    @has_param.setter
    def has_param(self, value):
        self._has_param = value

    @property
    def color_code(self):
        return self._color_code

    @color_code.setter
    def color_code(self, value):
        self._color_code = value

    @property
    def lang_name(self):
        return self._lang_name

    @lang_name.setter
    def lang_name(self, value):
        self._lang_name = value

    @property
    def color_char(self):
        return self._color_char

    @color_char.setter
    def color_char(self, value):
        self._color_char = value

class ClickEvent:
    def __init__(self, action, param):
        self.action = action
        self.param = param

class HoverEvent:
    def __init__(self, action, param):
        self.action = action
        self.param = param


class SkriptChatCodeEnum(SkriptChatCode):
    reset = SkriptChatCode()
    black = SkriptChatCode("black", '0')
    dark_blue = SkriptChatCode("dark_blue", 1)
    dark_green = SkriptChatCode("dark_green", 2)
    dark_aqua = SkriptChatCode("dark_aqua", "dark_cyan", 3)
    dark_red = SkriptChatCode("dark_red", '4')
    dark_purple = SkriptChatCode("dark_purple", '5')
    gold = SkriptChatCode("gold", "orange", '6')
    gray = SkriptChatCode("gray", "light_grey", 7)
    dark_gray = SkriptChatCode("dark_gray", "dark_grey", 8)
    blue = SkriptChatCode("blue", "light_cyan", 9)
    green = SkriptChatCode("green", "light_green", 'a')
    aqua = SkriptChatCode("aqua", "light_cyan", 'b')
    red = SkriptChatCode("red", "light_red", 'c')
    light_purple = SkriptChatCode("light_purple", 'd')
    yellow = SkriptChatCode("yellow", 'e')
    white = SkriptChatCode("white", 'f')

    bold = SkriptChatCode()
    italic = SkriptChatCode()
    underlined = SkriptChatCode(None, "underline")
    strikethrough = SkriptChatCode()
    obfuscated = SkriptChatCode(None, "magic")

    open_url = SkriptChatCode(True)
    run_command = SkriptChatCode(True)
    suggest_command = SkriptChatCode(True)
    change_page = SkriptChatCode(True)

    show_text = SkriptChatCode(True)
    font = SkriptChatCode(True)

    insertion = SkriptChatCode(True)


def update_component(component, param):
    # Default: do nothing
    pass

for code in [code for name, code in globals().items() if isinstance(code, type) and issubclass(code, SkriptChatCodeEnum)]:
    setattr(SkriptChatCodeEnum, code.__name__, code)
