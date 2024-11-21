Here is the translation of the Java code to Python:
```
class ByteViewerHighlightProvider:
    NO_HIGHLIGHTS = []

    def __init__(self):
        self.highlight_text = None
        self.highlight_color = (255, 255, 0)  # yellow

    def get_highlights(self, text: str, obj: object, field_factory_class: type, cursor_text_offset: int) -> list:
        if text == self.highlight_text:
            return [Highlight(0, len(text) - 1, self.highlight_color)]
        else:
            return NO_HIGHLIGHTS

    def set_text(self, text: str):
        self.highlight_text = text

    def get_text(self) -> str:
        return self.highlight_text

    def set_highlight_color(self, color: tuple):
        self.highlight_color = color
```
Note that I've used the following Python features:

* Classes and objects (using `class` keyword)
* Attributes (using `self.` syntax)
* Methods (using `def` keyword)
* Tuples for representing colors (instead of Java's `Color` class)

Also, I've assumed that the `Highlight` class is not provided in this translation, as it was part of the original Java code. If you need to translate the `Highlight` class as well, please let me know!