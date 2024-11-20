Here is the translation of the Java code to Python:

```Python
class ChangeTagOffsetPlan:
    def __init__(self):
        self.path = None
        self.offset = 0
        super().__init__()

    def __init__(self, partial_path=None, offset=0):
        if partial_path is not None and isinstance(partial_path, str):
            partial_path = PartialPath(partial_path)
        super().__init__()
        self.path = partial_path
        self.offset = offset

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        if not isinstance(value, (str, PartialPath)):
            raise TypeError("Invalid type for 'path'. It should be a string or an instance of 'PartialPath'.")
        self._path = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        if not isinstance(value, int) and not isinstance(value, float):
            raise TypeError("Invalid type for 'offset'. It should be an integer or a floating point number.")
        self._offset = value

    def get_paths(self):
        return [self.path] if self.path is not None else []

    def serialize_to_buffer(self, buffer):
        buffer.put(int(ChangeTagOffsetPlanType.CHANGE_TAG_OFFSET))
        ChangeTagOffsetPlan.serialize_string(buffer, self.path.get_full_path())
        buffer.put_long(self.offset)

    @staticmethod
    def serialize_string(buffer, string):
        if isinstance(string, str):
            for char in string:
                buffer.put(ord(char))

    @classmethod
    def deserialize_from_buffer(cls, buffer):
        path = None
        offset = 0

        type_ = buffer.get()
        if type_ == ChangeTagOffsetPlanType.CHANGE_TAG_OFFSET:
            path = cls.deserialize_string(buffer)
            offset = buffer.get_long()

        return cls(path, offset)

    @staticmethod
    def deserialize_string(buffer):
        string = ""
        while True:
            char_code = buffer.get()
            if char_code < 0 or char_code > 127:
                break
            string += chr(char_code)
        return string

    def __str__(self):
        return f"ChangeTagOffsetPlan({self.path}, {self.offset})"

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, ChangeTagOffsetPlan):
            return False
        return hash((self.path, self.offset)) == hash((other.path, other.offset))

    def __hash__(self):
        return hash((self.path, self.offset))
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by explicitly calling the parent class' constructor in the child class and then defining the overridden methods with the same name as those in the parent class.

Also note that Python does not support operator overloading like Java, so I did not translate the `OperatorType` enum from your original code to a similar construct.