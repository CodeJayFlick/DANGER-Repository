Here is the translation of the Java code to Python:
```
class TrimmingWhitespaceHandler:
    def count_spaces(self, s: str, offset: int) -> int:
        for i in range(offset, len(s)):
            if not s[i].isspace():
                return i - offset
        return len(s) - offset  # all whitespace

    def trim(self, s: str) -> str:
        return s.strip()
```
Note that I've kept the same method names and variable names as in the original Java code to make it easier to compare. However, Python is a dynamically-typed language, so you don't need to specify types for variables or function parameters like you do in Java.

Also, note that `Character.isWhitespace()` has been replaced with `str.isspace()`, which does essentially the same thing but is more concise and idiomatic in Python.