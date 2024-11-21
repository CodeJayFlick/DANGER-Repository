class WrappedFont:
    FAMILY = "family"
    SIZE = "size"
    STYLE = "style"

    def __init__(self, font=None):
        self.font = font if font else None

    @property
    def object(self):
        return self.font

    def read_state(self, save_state):
        family = save_state.get(FAMILY, "monospaced")
        size = int(save_state.get(SIZE, 12))
        style = int(save_state.get(STYLE, 0))  # Assuming Font.PLAIN is equivalent to 0
        font = font_class(family, style, size)
        self.font = font

    def write_state(self, save_state):
        family = self.font.getfamily()
        pos = family.find(".")
        if pos > 0:
            family = family[:pos]
        save_state[FAMILY] = family
        save_state[SIZE] = self.font.size
        save_state[STYLE] = self.font.style

    def get_option_type(self):
        return "FONT_TYPE"


# Assuming you have a font class like this in your Python environment:
class FontClass:
    def __init__(self, family, style, size):
        pass  # You would implement the actual logic for creating a font here
