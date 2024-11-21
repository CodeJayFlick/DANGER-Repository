Here is the translation of the Java code into Python:

```Python
class ROMHeader:
    def __init__(self):
        self.file_header = None
        self.optional_header = None

    @property
    def file_header(self):
        return self._file_header

    @file_header.setter
    def file_header(self, value):
        self._file_header = value

    @property
    def optional_header(self):
        return self._optional_header

    @optional_header.setter
    def optional_header(self, value):
        self._optional_header = value


class FileHeader:
    pass


class OptionalHeaderROM:
    pass
```

Note that in Python, we don't have a direct equivalent of Java's `private` access modifier. Instead, we use the underscore prefix to indicate that an attribute is intended to be private (i.e., not accessed directly from outside the class). The `@property` decorator allows us to create getter and setter methods for these attributes.

Also note that I didn't translate the entire code file - only the specific Java classes you provided.