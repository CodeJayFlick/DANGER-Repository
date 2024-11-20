Here is the translation of the Java code to Python:
```
import re

class StringStartsWithColumnConstraint:
    def __init__(self, pattern_string):
        super().__init__(pattern_string)

    @property
    def name(self):
        return "Starts With"

    def copy(self, new_pattern_string):
        return type(self)(new_pattern_string)

    def generate_matches_pattern(self, pattern_string):
        return re.compile(f"^{re.escape(pattern_string)}", re.IGNORECASE)
```
Note that I've used the `re` module for regular expressions in Python. The `generate_matches_pattern` method uses the `^` anchor to match strings that start with the given pattern string, and `re.IGNORECASE` to make the matching case-insensitive.

Also, since there is no direct equivalent of Java's `Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE`, I've used a single flag `re.IGNORECASE` which combines both cases.