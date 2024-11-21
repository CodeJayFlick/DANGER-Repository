class GLabel:
    def __init__(self):
        self.label = JLabel()
        self.init()

    def init(self):
        self.set_html_rendering_enabled(False)

    @staticmethod
    def from_string(text: str) -> 'GLabel':
        label = JLabel(text)
        return GLabel(label, SwingConstants.LEADING)

    @staticmethod
    def from_text_and_alignment(text: str, alignment: int) -> 'GLabel':
        label = JLabel(text, alignment)
        return GLabel(label, alignment)

    @staticmethod
    def from_text_icon_and_alignment(text: str, icon: Icon, alignment: int) -> 'GLabel':
        label = JLabel(text, icon, alignment)
        return GLabel(label, icon, alignment)


class JLabel:
    def __init__(self):
        pass

    def set_html_rendering_enabled(self, enabled: bool):
        # This method is not implemented in the original Java code
        pass


def main():
    g_label = GLabel()
    print(g_label.label.getText())  # prints nothing because no text was provided during initialization


if __name__ == "__main__":
    main()

