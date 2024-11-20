Here is the translation of the given Java code into Python:

```Python
class DebugFixupElement:
    SIZEOF = 12

    def __init__(self):
        self.type = None
        self.addr1 = None
        self.addr2 = None

    @classmethod
    def create_debug_fixup_element(cls, reader, index):
        debug_fixup_element = cls()
        debug_fixup_element.init_debug_fixup_element(reader, index)
        return debug_fixup_element

    def init_debug_fixup_element(self, reader, index):
        self.type = reader.read_int(index); index += 4
        self.addr1 = reader.read_int(index); index += 4
        self.addr2 = reader.read_int(index); index += 4

    @property
    def type_(self):
        return self.type

    @type_.getter
    def get_type(self):
        return self.type

    @property
    def addr1_(self):
        return self.addr1

    @addr1_.getter
    def get_addr1(self):
        return self.addr1

    @property
    def addr2_(self):
        return self.addr2

    @addr2_.getter
    def get_addr2(self):
        return self.addr2


class Reader:
    def read_int(self, index):
        # implement your own reading logic here
        pass
```

Note that I've made some assumptions about the `Reader` class and its methods. In a real-world scenario, you would need to replace these with actual implementations of file reading or binary data parsing.

Also note that Python does not have direct equivalent for Java's "final" keyword. The closest approximation is using properties (getter/setter) as shown in this code.