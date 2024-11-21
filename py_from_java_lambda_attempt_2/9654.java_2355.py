Here is the translation of the given Java interface into a Python class:

```Python
class GComponent:
    HTML_DISABLE_STRING = "html.disable"

    def set_html_rendering_enabled(self, enabled):
        self.set_html_rendering_flag(self, enabled)

    @property
    def html_rendering_enabled(self):
        prop = getattr(self, 'getClientProperty', lambda x: None)(HTML_DISABLE_STRING)
        return prop is None or prop != True

    @staticmethod
    def warn_about_html_text(text):
        if text.lower().startswith("<html>"):
            print(f"Warning: HTML text detected in non-HTML component: {text}")

    @staticmethod
    def set_html_rendering_flag(comp, enabled):
        comp.putClientProperty(HTML_DISABLE_STRING, None if enabled else True)
```

Note that Python does not have direct equivalents for Java's `public`, `default`, and `static` keywords. The equivalent concepts in Python are:

- Public: No keyword needed; methods can be accessed directly from the class.
- Default: In Python, this is achieved using a property decorator (`@property`) to create getter and setter methods.
- Static: This is also not necessary in Python as static methods can be defined without any special syntax.