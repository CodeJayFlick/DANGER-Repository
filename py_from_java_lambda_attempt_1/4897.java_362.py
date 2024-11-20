Here is the translation of the Java code to Python:
```
class RelocationOSFixup:
    def __init__(self, reader):
        self.fixup_type = reader.read_short()
        self.zeropad = reader.read_short()

    @property
    def fixup_type(self):
        return self.fixup_type

    @property
    def pad(self):
        return self.zeropad


class BinaryReader:
    def read_short(self):
        # implement reading a short integer from the binary data
        pass
```
Note that I've created a `BinaryReader` class in Python, which is equivalent to the Java class. In this implementation, you would need to provide your own logic for reading a short integer from the binary data.

Also, I've used Python's property decorator (`@property`) to create getter methods for the `fixup_type` and `pad` attributes. This allows you to access these attributes as if they were public properties in Java.