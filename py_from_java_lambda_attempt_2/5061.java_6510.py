Here is the translation of the Java code into Python:

```Python
class DataSym32:
    def __init__(self):
        self.type_index = None
        self.name_char = None

    @classmethod
    def create_data_sym32(cls, length, type, reader, ptr):
        data_sym32 = cls()
        data_sym32.init_data_sym32(length, type, reader, ptr)
        return data_sym32

    def init_data_sym32(self, length, type, reader, ptr):
        self.process_debug_symbol(length, type)

        self.offset = reader.read_int(ptr); ptr += 4
        self.section = reader.read_short(ptr); ptr += 2
        self.type_index = reader.read_short(ptr); ptr += 2
        self.name_char = reader.read_byte(ptr); ptr += 1
        self.name = reader.read_ascii_string(ptr)
        ptr += len(self.name)

    def get_type_index(self):
        return self.type_index

    def get_name_char(self):
        return self.name_char


class Reader:
    @staticmethod
    def read_int(ptr):
        # implement your own int reading logic here
        pass

    @staticmethod
    def read_short(ptr):
        # implement your own short reading logic here
        pass

    @staticmethod
    def read_byte(ptr):
        # implement your own byte reading logic here
        pass

    @staticmethod
    def read_ascii_string(ptr):
        # implement your own ascii string reading logic here
        pass


class FactoryBundledWithBinaryReader:
    @classmethod
    def create(cls, data_sym32_class):
        return cls()
```

Please note that the `process_debug_symbol` method and all the methods in the `Reader` class are not implemented as they were present in the original Java code. You would need to implement your own logic for these methods based on how you want them to behave.

Also, this translation assumes that there is no equivalent of Java's `extends DebugSymbol` in Python. If you have a similar concept in Python (like inheritance), please let me know and I can modify the code accordingly.