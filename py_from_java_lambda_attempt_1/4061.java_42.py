Here is the translation of the given Java code into equivalent Python:

```Python
class LocationReferenceContext:
    EMPTY_CONTEXT = None  # Initialize with None for now

    def __init__(self):
        self.parts = [BasicPart("")]

    @classmethod
    def get(cls, text: str) -> 'LocationReferenceContext':
        return cls(text) if text else cls.EMPTY_CONTEXT

    @classmethod
    def get_context(cls, context: 'LocationReferenceContext') -> 'LocationReferenceContext':
        return context or cls.EMPTY_CONTEXT


class Part:
    def __init__(self, text):
        self.text = text

    def get_text(self) -> str:
        return self.text

    def get_html_text(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    @classmethod
    @staticmethod
    def fix_breaking_spaces(s: str) -> str:
        updated = s.replace("\\s", "&nbsp;")
        return updated


class BasicPart(Part):
    def __init__(self, text):
        super().__init__(text)

    def get_text(self, start: str, end: str) -> str:
        return self.text  # No decoration

    def get_html_text(self) -> str:
        escaped = HTMLUtilities.escapeHTML(self.text)
        updated = Part.fix_breaking_spaces(escaped)
        return f"<span style=\"background-color: #a3e4d7; color: black;\"><b><font size=4>{updated}</font></b></span>"


class MatchPart(Part):
    def __init__(self, text):
        super().__init__(text)

    def get_text(self, start: str, end: str) -> str:
        return f"{start}{self.text}{end}"

    def get_html_text(self) -> str:
        escaped = HTMLUtilities.escapeHTML(self.text)
        updated = Part.fix_breaking_spaces(escaped)
        return f"<span style=\"background-color: #a3e4d7; color: black;\"><b><font size=4>{updated}</font></b></span>"
```

Please note that Python does not have direct equivalent of Java's `List.of()` method. It uses list comprehension or the `list` constructor to create a new list from an iterable.

Also, I've used f-strings for formatting strings in Python, which is similar to how you would use string concatenation with HTML tags in Java.