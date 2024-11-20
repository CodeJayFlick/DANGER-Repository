Here is the translation of the Java code into Python:

```Python
class MDObjectReserved:
    def __init__(self, dmang):
        super().__init__(dmang)

    def insert(self, builder):
        super().insert(builder)

    def parse_internal(self):
        # Go to end of string.
        self.dmang.increment(len(self.dmang.mangled_symbol) - self.dmang.index)


class MDMang:
    pass


def parse_digits(dmang):
    ret = ""
    while dmang.peek() >= '0' and dmang.peek() <= '9':
        ret += dmang.get_and_increment()
    return ret
```

Note that I've created a separate class `MDMang` in Python, as there is no direct equivalent to Java's `package mdemangler. MDMang;`. In Python, you can define classes and functions independently without needing packages or imports.

Also note that the `parseInternal()` method has been renamed to `parse_internal()`, following standard Python naming conventions for methods (lowercase with underscores).