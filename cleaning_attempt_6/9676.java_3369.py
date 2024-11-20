class GHtmlLabel:
    def __init__(self):
        pass

    def __init__(self, text):
        self.text = text

    def __init__(self, text, horizontal_alignment):
        self.text = text
        self.horizontal_alignment = horizontal_alignment

    def __init__(self, text, icon, horizontal_alignment):
        self.text = text
        self.icon = icon
        self.horizontal_alignment = horizontal_alignment

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        if not isinstance(value, str) or len(value.strip()) == 0:
            Msg.warn("Trying to set text on an immutable label!")
            return
        self._text = value


class JLabel:
    pass


Msg = object()
ReflectionUtilities = object()

if __name__ == "__main__":
    ghtml_label = GHtmlLabel("Hello, World!", SwingConstants.LEFT)
