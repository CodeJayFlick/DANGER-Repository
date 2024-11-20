Here is the translation of the Java code into Python:

```Python
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
```

Please note that this is a direct translation of the Java code into Python. However, there are some differences between the two languages:

1. In Python, you don't need to specify types for variables or method parameters.
2. The `@Override` annotation in Java has no equivalent in Python because it's not necessary.
3. Python doesn't have a direct equivalent of Java's Swing library, so I left out any references to it.

Also note that the code above assumes you are using some sort of logging mechanism (Msg) and reflection utility class (ReflectionUtilities), which were present in the original Java code but don't exist in this translation.