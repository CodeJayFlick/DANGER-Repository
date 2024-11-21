Here is the translation of the Java code into Python:

```Python
class StringField:
    NULL_VALUE = None
    INSTANCE = NULL_VALUE

    ENCODING = "UTF-8"

    def __init__(self):
        self.str = None
        self.bytes = None

    def __init__(self, str_value=None, immutable=False):
        super().__init__()
        if str_value is not None:
            do_set_string(str_value)
        else:
            set_null()

    @staticmethod
    def do_set_string(str_value):
        StringField.__init__.str = str_value
        try:
            StringField.__init__.bytes = (str_value.encode(STRINGField.ENCODING) if str_value is not None else None)
        except UnsupportedEncodingException as e:
            raise AssertException(e)

    @property
    def null(self):
        return self.bytes is None

    def set_null(self):
        check_immutable()
        StringField.__init__.str = None
        StringField.__init__.bytes = None

    @property
    def string_value(self):
        return self.str

    def set_string(self, str_value):
        check_immutable()
        do_set_string(str_value)

    def length(self):
        if self.bytes is None:
            return 4
        else:
            return len(self.bytes) + 4

    def write(self, buf, offset):
        if self.bytes is None:
            return buf.put_int(offset, -1)
        else:
            offset = buf.put_int(offset, len(self.bytes))
            return buf.put[offset:offset+len(self.bytes)], len(self.bytes)

    def read(self, buf, offset):
        check_immutable()
        length = buf.get_int(offset)
        if length < 0:
            self.str = None
            self.bytes = None
        else:
            self.bytes = buf.get_bytes(offset+4, length)
            self.str = bytes.decode(STRINGField.ENCODING) if self.bytes is not None else None

    def read_length(self, buf, offset):
        return buf.get_int(offset)

    @property
    def variable_length(self):
        return True

    @property
    def field_type(self):
        return "string"

    def __str__(self):
        return f"StringField: {self.str}"

    def get_value_as_string(self):
        if self.str is None:
            return "null"
        else:
            return f'"{self.str}"'

    def equals(self, obj):
        if not isinstance(obj, StringField):
            return False
        other = StringField()
        if self.str is None and other.str is None:
            return True
        elif self.str is None or other.str is None:
            return False
        else:
            return self.str == other.str

    def get_binary_data(self):
        return self.bytes

    def set_binary_data(self, bytes_value):
        check_immutable()
        if bytes_value is not None:
            try:
                self.str = bytes.decode(STRINGField.ENCODING)
            except UnsupportedEncodingException as e:
                raise AssertException(e)

    def truncate(self, length):
        max_len = length - 4
        if self.str and len(self.str) > max_len:
            set_string(self.str[:max_len])

    def compare_to(self, o):
        other = StringField()
        try:
            other.read(o)
        except IOException as e:
            raise AssertException(e)

        return self.compare_to(other)

    def copy_field(self):
        return StringField(self.str)

    def new_field(self):
        return StringField()

    @property
    def hash_code(self):
        if self.str is None:
            return 0
        else:
            return self.str.encode().hexdigest()
```

Please note that the Python code does not include all the methods from the Java code. Some of them were removed because they are either redundant or do not have a direct equivalent in Python.