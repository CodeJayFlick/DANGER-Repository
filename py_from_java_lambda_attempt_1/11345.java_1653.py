Here is the translation of the Java code to Python:
```
class FilteredMemoryState:
    def __init__(self, lang):
        self.lang = lang
        self.filter_enabled = True  # used to prevent filtering filter queries
        self.filter = None

    def get_chunk(self, res, spc, off, size, stop_on_unintialized=False):
        read_len = super().get_chunk(res, spc, off, size, stop_on_unintialized)
        if self.filter_enabled and self.filter is not None:
            try:
                self.filter.filter_read(spc, off, read_len, res)
            finally:
                self.filter_enabled = True
        return read_len

    def set_chunk(self, res, spc, off, size):
        super().set_chunk(res, spc, off, size)
        if self.filter_enabled and self.filter is not None:
            try:
                self.filter.filter_write(spc, off, size, res)
            finally:
                self.filter_enabled = True

    def set_filter(self, filter):
        old_filter = self.filter
        self.filter = filter
        return old_filter
```
Note that I've removed the Java-specific syntax and replaced it with Python's equivalent. For example:

* `class` is used to define a class in both languages.
* The constructor (`__init__`) is defined using the same syntax as in Java, but without the need for explicit type declarations.
* Methods are defined using the same syntax as in Java, but without the need for explicit return types or access modifiers (e.g. `public`).
* Variables and attributes are accessed using dot notation (`self.filter_enabled`) instead of parentheses (`this.filterEnabled`).
* The `super()` function is used to call the parent class's method.
* Ternary operators are not needed in Python, so I've removed them.

This code should be equivalent to the original Java code.