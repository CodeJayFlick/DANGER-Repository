Here is the translation of the given Java code into equivalent Python:

```Python
class DataTypeLine:
    def __init__(self, name: str, type: str, comment: str, data_type: object):
        self.data_type = data_type
        if not name:
            name = ""
        self.name = name
        self.type = type
        self.comment = comment if comment else ""

    @property
    def get_data_type(self) -> object:
        return self.data_type

    @property
    def get_name(self) -> str:
        return self.name

    @property
    def get_comment(self) -> str:
        return self.comment

    @property
    def has_universal_id(self) -> bool:
        if not self.data_type:
            return False
        universal_id = self.data_type.get_universal_id()
        return universal_id and universal_id.value != 0

    @property
    def get_type_color(self):
        return self.type_color

    @get_type_color.setter
    def set_type_color(self, color: object):
        self.type_color = color

    @property
    def get_name_color(self) -> object:
        return self.name_color

    @get_name_color.setter
    def set_name_color(self, color: object):
        self.name_color = color

    @property
    def get_comment_color(self) -> object:
        return self.comment_color

    @get_comment_color.setter
    def set_comment_color(self, color: object):
        self.comment_color = color

    def set_all_colors(self, diff_color: object):
        self.set_name_color(diff_color)
        self.set_type_color(diff_color)
        self.set_comment_color(diff_color)

    def update_color(self, other_validatable_line: 'DataTypeLine', invalid_color: object) -> None:
        if not invalid_color:
            raise ValueError("Color cannot be null")
        if not other_validatable_line:
            self.name_color = invalid_color
            self.type_color = invalid_color
            self.comment_color = invalid_color
            return

        if type(other_validatable_line) != DataTypeLine:
            raise AssertionError("DataTypeLine can only be matched against other DataTypeLine implementations.")
        other_line = other_validatable_line

        if not other_line.matches_name(self.name):
            self.set_name_color(invalid_color)
            other_line.set_name_color(invalid_color)

        if not other_line.matches_type(self.type):
            self.set_type_color(invalid_color)
            other_line.set_type_color(invalid_color)

        if not other_line.matches_comment(self.comment):
            self.set_comment_color(invalid_color)
            other_line.set_comment_color(invalid_color)

    def matches_name(self, other_name: str) -> bool:
        return self.name == other_name

    def matches_type(self, other_type: str) -> bool:
        return self.type == other_type

    def matches_comment(self, other_comment: str) -> bool:
        return self.comment == other_comment

    @property
    def is_validated(self) -> bool:
        return self.validation_line is not None

    @property
    def get_text(self) -> str:
        return f"{self.type} {self.name} {self.comment}"

    def __str__(self):
        max_length = max(len(self.type), len(self.name), len(self.comment))
        color_string = "" if self.type_color is None else " (colored)"
        name_string = f"{' ' * (max_length - len(self.name))}{self.name} {color_string}"
        comment_string = f"{' ' * (max_length - len(self.comment))}{self.comment} {color_string}"

        return f"\ntype:     {' ' * (max_length - len(self.type))}{self.type}{color_string}\nname:     {name_string}\ncomment:  {comment_string}\n"

    def length(self, s: str) -> int:
        if not s:
            return 0
        return len(s)

    @staticmethod
    def pad(actual: str, size: int) -> str:
        diff = size - actual.length()
        return " " * abs(diff) + actual

    def __eq__(self, other_validatable_line):
        if not other_validatable_line:
            return False

        if type(other_validatable_line) != DataTypeLine:
            raise AssertionError("DataTypeLine can only be matched against other DataTypeLine implementations.")
        other_line = other_validatable_line

        return other_line.matches_name(self.name) and other_line.matches_type(self.type) and other_line.matches_comment(self.comment)

    def set_validation_line(self, line: 'ValidatableLine'):
        if self.validation_line == line:
            return  # already set
        self.validation_line = line
        line.set_validation_line(self)
        self.update_color(line, INVALID_COLOR)
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. However, the method names and their order in this code are consistent with those in the original Java code, which should help maintainers understand how these methods relate to each other.