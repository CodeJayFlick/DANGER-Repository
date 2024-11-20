Here is the translation of the Java code to Python:
```
import re

class StringNotContainsColumnConstraint:
    def __init__(self, spec):
        super().__init__(spec)

    @property
    def name(self):
        return "Does Not Contain"

    @property
    def group(self):
        return "z string"

    def accepts(self, value: str, context) -> bool:
        return not super().accepts(value, context)

    def copy(self, new_pattern_string: str) -> 'StringNotContainsColumnConstraint':
        return StringNotContainsColumnConstraint(new_pattern_string)

    def generate_finds_pattern(self):
        return re.compile("(.*)")
```
Note that I've used the `re` module for regular expressions in Python.