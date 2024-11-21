Here is the translation of the given Java code into equivalent Python:

```Python
class GnuVerneed:
    def __init__(self):
        self.vn_version = 0
        self.vn_cnt = 0
        self.vn_file = 0
        self.vn_aux = 0
        self.vn_next = 0

    @classmethod
    def from_reader(cls, reader):
        try:
            cls.vn_version = reader.read_short()
            cls.vn_cnt = reader.read_short()
            cls.vn_file = reader.read_int()
            cls.vn_aux = reader.read_int()
            cls.vn_next = reader.read_int()
        except Exception as e:
            print(f"Error: {e}")

    def get_version(self):
        return self.vn_version

    def get_cnt(self):
        return self.vn_cnt

    def get_file(self):
        return self.vn_file

    def get_aux(self):
        return self.vn_aux

    def get_next(self):
        return self.vn_next


class DataType:
    pass
```

Note that the `toDataType` method from Java does not have a direct equivalent in Python. The code provided is for creating an instance of the class and accessing its attributes, which are similar to what was done in the original Java code.

The `from_reader` method has been added as it seems like you were trying to read data from some kind of binary reader in your original Java code.