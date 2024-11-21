class GDLabel:
    def __init__(self):
        self.label = JLabel()
        self.init()

    def init(self):
        pass  # equivalent to super() in Java


# Note: In Python, we don't have a direct equivalent for Java's Swing classes.
# We can use tkinter or PyQt libraries which are similar but not identical.

class GComponent:
    @staticmethod
    def warn_about_html_text(text):
        print(f"Warning: HTML text '{text}' is being used.")

    @classmethod
    def set_html_rendering_enabled(cls, enabled):
        pass  # equivalent to super().setHTMLRenderingEnabled() in Java


# Note: Python doesn't have a direct equivalent for Java's JLabel class.
# We can use tkinter or PyQt libraries which are similar but not identical.

class JLabel:
    def __init__(self):
        self.text = ""

    def set_text(self, text):
        GComponent.warn_about_html_text(text)
        self.text = text

