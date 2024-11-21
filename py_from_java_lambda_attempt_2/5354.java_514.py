Here is the translation of the Java code to Python:

```Python
class TextLine:
    def __init__(self, text):
        self.text = text

    def copy(self):
        return TextLine(self.text)

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        if not isinstance(value, str):
            raise TypeError("Text must be a string")
        self._text = value

    @property
    def is_diff_colored(self):
        return self.text_color is not None

    @property
    def text_color(self):
        return self._text_color

    @text_color.setter
    def text_color(self, color):
        if not isinstance(color, tuple) and len(color) == 3:
            raise TypeError("Color must be a RGB tuple")
        self._text_color = color

    def matches(self, other_line):
        return self.text.lower() == other_line.text.lower()

    @property
    def is_validated(self):
        return self.validation_line is not None

    def update_color(self, other_line, invalid_color):
        if invalid_color is None:
            raise TypeError("Color cannot be null")
        if other_line is None:
            self.text_color = invalid_color
            return
        if not isinstance(other_line, TextLine):
            raise ValueError("TextLine can only be matched against another TextLine implementation.")
        if not self.matches(other_line):
            self.text_color = invalid_color
            other_line.text_color = invalid_color

    def set_validation_line(self, line):
        if self.validation_line == line:
            return  # already set
        self.validation_line = line
        line.set_validation_line(self)
        self.update_color(line, (255,0,0))  # assuming INVALID_COLOR is RGB(255,0,0)

    def __str__(self):
        color_str = ""
        if self.text_color:
            color_str += " " + str(self.text_color)
        return f"{self.text}{color_str}"

    def __eq__(self, other):
        if not isinstance(other, TextLine):
            return False
        return self.text.lower() == other.text.lower()

    def __hash__(self):
        prime = 31
        result = 1
        result *= prime + (0 if self.text is None else hash(self.text))
        result *= prime + (0 if self.text_color is None else hash(tuple(self.text_color)))
        return result

class ValidatableLine:
    pass
```

Please note that Python does not have a direct equivalent of Java's `ValidatableLine` interface. In the above code, I've defined an empty class called `ValidatableLine`.