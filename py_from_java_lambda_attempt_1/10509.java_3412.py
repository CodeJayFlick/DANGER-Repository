Here is the translation of the given Java code into Python:

```Python
class JavaSourceLine:
    def __init__(self, line: str, line_number: int):
        self.line_text = line
        self.original_text = line
        self.line_number = line_number
        self.is_deleted = False

    @property
    def line_number(self) -> int:
        return self._line_number

    @line_number.setter
    def line_number(self, value: int):
        self._line_number = value

    @property
    def is_deleted(self) -> bool:
        return self._is_deleted

    @is_deleted.setter
    def is_delete(self, value: bool):
        self._is_deleted = value

    def delete(self):
        self.line_text = ""
        self.is_deleted = True

    def get_leading_whitespace(self) -> str:
        if not self.line_text:
            return ""

        leading_whitespace = ""
        for char in self.line_text:
            if not char.isspace():
                break
            leading_whitespace += char

        return leading_whitespace

    @property
    def is_deleted_(self) -> bool:
        return self._is_deleted_

    def get_text(self) -> str:
        return self.line_text

    def prepend(self, text: str):
        self.line_text = text + self.line_text
        self.is_deleted = False

    def append(self, text: str):
        self.line_text += text
        self.is_deleted = False

    def set_text(self, text: str):
        self.line_text = text
        self.is_deleted = False

    @property
    def has_changes(self) -> bool:
        return self.original_text != self.line_text

    def __str__(self) -> str:
        return self.line_text

    def create_original_clone(self) -> 'JavaSourceLine':
        return JavaSourceLine(self.original_text, self.line_number)

    @property
    def original_text_(self) -> str:
        return self._original_text_

    def get_original_text(self) -> str:
        return self.original_text_
```

Note that Python does not have direct equivalent of private/public variables like in Java. The `@property` decorator is used to create getter and setter methods for the attributes, which can be accessed as if they were public properties.