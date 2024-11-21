Here is the translation of the given Java code into Python:

```Python
class OmfCommentRecord:
    def __init__(self, reader):
        self.read_record_header(reader)
        self.comment_type = reader.read_next_byte()
        self.comment_class = reader.read_next_byte()
        bytes_array = reader.read_next_bytes(get_record_length() - 3)  # May not be a string, depending on commentClass
        if (self.comment_class == 0 or self.comment_class == 143):  # equivalent to byte values 0 and 0xA3 in Java
            len = bytes_array[0] & 0xFF
            self.value = ''.join([chr(x) for x in bytes_array[1:1+len]])  # This is the translator/libmod string

    def get_comment_class(self):
        return self.comment_class

    def get_value(self):
        return self.value


def read_record_header(reader):
    pass  # equivalent to Java method, but not implemented here as it's not provided in the given code


def get_record_length():
    pass  # equivalent to Java method, but not implemented here as it's not provided in the given code
```

Please note that Python does not have direct equivalents for some of the Java classes and methods used in this code. For example, `BinaryReader` is a custom class in Java which reads binary data from an input stream. In Python, you would typically use built-in functions like `open()` to read files or libraries like `struct` to parse binary data.

Also note that I have not implemented the `read_record_header()` and `get_record_length()` methods as they are not provided in the given code.