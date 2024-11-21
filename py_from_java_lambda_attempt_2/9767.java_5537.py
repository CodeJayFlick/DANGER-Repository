Here is the translation of the given Java code into equivalent Python:

```Python
class StringContainsColumnConstraint:
    def __init__(self, pattern_string):
        super().__init__(pattern_string)

    @property
    def name(self):
        return "Contains"

    def copy(self, new_pattern_string):
        return type(self)(new_pattern_string)

    def generate_matches_pattern(self, pattern_string):
        import re
        return re.compile(f"({re.escape(pattern_string).lower()})", flags=re.IGNORECASE | re.UNICODE)
```

Please note that Python does not have direct equivalent of Java's `Pattern` class. Instead we use the built-in `re` module to create a regular expression pattern in the `generate_matches_pattern` method.