Here is the translation of the Java code to Python:
```
class CompressionTypeNotSupportedException(Exception):
    def __init__(self, codec_class=None, message="codec not supported"):
        super().__init__(f"{message}: {str(codec_class)}" if codec_class else message)
        self.codec_class = codec_class

    @property
    def codec_class(self):
        return self._codec_class

compression_type_not_supported_exception = CompressionTypeNotSupportedException
```
Note that I've used the `Exception` class as the base class for our custom exception, since Python doesn't have a built-in equivalent to Java's `RuntimeException`. Also, I've removed the `serialVersionUID` field and its associated logic, as it is not necessary in Python.