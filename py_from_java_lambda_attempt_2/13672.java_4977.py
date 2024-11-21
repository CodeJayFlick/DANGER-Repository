Here is the translation of the Java code to Python:
```
class DmgInputStream:
    def __init__(self, stream):
        self.stream = stream

    @property
    def length(self):
        return self.stream.length()

    def read(self):
        try:
            return self.stream.read()
        except Exception as e:
            raise IOError(str(e))

    def readinto(self, b):
        try:
            return self.stream.read(b)
        except Exception as e:
            raise IOError(str(e))

    def readinto(self, b, off, len):
        try:
            return self.stream.read(b, off, len)
        except Exception as e:
            raise IOError(str(e))
```
Note that I've used Python's built-in `property` decorator to create a getter for the `length` attribute. This is equivalent to Java's `public long getLength()` method.

I've also replaced the `throws IOException` syntax with Python's exception handling mechanism, using try-except blocks to catch and re-raise exceptions as `IOError`.

Finally, I've used Python's built-in `bytearray` type (aliased as `b`) instead of Java's `byte[]`.