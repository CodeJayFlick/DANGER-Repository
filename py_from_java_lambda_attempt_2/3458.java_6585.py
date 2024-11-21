Here is the translation of the Java code to Python:
```
class FilterState:
    def __init__(self, bookmark_types: set):
        self.bookmark_types = bookmark_types

    @property
    def bookmark_types(self) -> set:
        return self.bookmark_types
```
Note that I've used type hints for the `bookmark_types` parameter and the `bookmark_types` property in Python 3.5+. If you're using an earlier version of Python, you can omit these.

Also, I've used a property (i.e., a getter) to provide read-only access to the `bookmark_types` attribute. This is equivalent to the Java code's `getBookmarkTypes()` method.