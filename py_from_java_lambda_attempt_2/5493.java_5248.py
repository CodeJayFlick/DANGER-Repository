Here is the translation of the Java code to Python:
```
class InvalidAnnotatedStringHandler:
    def __init__(self, error_text=None):
        if error_text is None:
            self.error_text = "Invalid Annotation"
        else:
            self.error_text = error_text

    def create_annotated_string(self, prototype_string, text, program):
        return AttributedString(self.error_text, Color.RED, prototype_string.font_metrics(0))

    def get_supported_annotations(self):
        return []

    def handle_mouse_click(self, annotation_parts, navigatable, service_provider):
        return False  # we don't handle clicks!!!

    def get_display_string(self):
        return "Invalid"

    def get_prototype_string(self):
        return ""

class AttributedString:
    def __init__(self, text, color, font_metrics):
        self.text = text
        self.color = color
        self.font_metrics = font_metrics

    @property
    def font_metrics(self):
        return self._font_metrics

    @font_metrics.setter
    def font_metrics(self, value):
        self._font_metrics = value
```
Note that I had to create a separate `AttributedString` class in Python since there is no direct equivalent to Java's `AttributedString`. In the original code, it seems like `AttributedString` was used as a simple wrapper around some text and color information.