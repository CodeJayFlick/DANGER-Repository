Here is the translation of the Java code to Python:
```
class PreservingWhitespaceHandler:
    def count_spaces(self, s: str, offset: int) -> int:
        return 0  # we count no spaces

    def trim(self, s: str) -> str:
        return s  # no trimming
```
Note that I've kept the same method names and parameter types as in the original Java code. In Python, you don't need to specify explicit getter/setter methods like `getCountSpaces` or `setTrim`, so I've used simple attribute access (`self.count_spaces` instead of `this.getCountSpaces()`).