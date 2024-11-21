Here is the translation of the given Java code into Python:

```Python
class StringEndsWithColumnConstraint:
    def __init__(self, pattern_string):
        super().__init__(pattern_string)

    @property
    def name(self):
        return "Ends With"

    def copy(self, new_pattern_string):
        return type(self)(new_pattern_string)

    def generate_matches_pattern(self, pattern_string):
        import re
        return re.compile(pattern_string, flags=re.I | re.U)
```

Note that Python does not have an exact equivalent to Java's `Pattern` class. Instead, we use the built-in `re` module for regular expressions and create a compiled regex object with the desired flags (`re.I` for case-insensitive matching and `re.U` for Unicode-aware matching).