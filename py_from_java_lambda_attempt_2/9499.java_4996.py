Here is the translation of the Java code into Python:

```Python
class GCheckBox(JCheckBox):
    def __init__(self):
        super().__init__()
        self.init()

    def init(self):
        self.set_html_rendering_enabled(False)

    @property
    def html_rendering_enabled(self):
        return False

    def set_html_rendering_enabled(self, enabled: bool) -> None:
        pass  # Not implemented in Python Swing

    def setText(self, text: str) -> None:
        GComponent.warn_about_html_text(text)
        super().setText(text)

class GComponent:
    @staticmethod
    def warn_about_html_text(text):
        print(f"Warning: HTML text '{text}' detected in non-HTML enabled checkbox.")
```

Please note that Python's Swing library does not support the `setHTMLRenderingEnabled` method, so I have left it as a placeholder.