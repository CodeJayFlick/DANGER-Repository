from javax.swing import JLabel, SwingConstants
import html.parser  # for HTML rendering


class GDHtmlLabel(JLabel):
    def __init__(self):
        super().__init__()

    def __init__(self, text: str):
        super(text)

    def __init__(self, text: str, horizontal_alignment: int):
        super(text, horizontal_alignment)

    def __init__(self, text: str, icon=None, horizontal_alignment=0):
        if icon is None:
            super(text)
        else:
            super(text, icon, horizontal_alignment)


# Example usage
gdhtml_label = GDHtmlLabel("Hello World")
print(gdhtml_label.getText())  # prints "Hello World"
