Here is the translation of the given Java code into Python:

```Python
class CoffRelocation:
    SIZEOF2 = 12
    SIZEOF = 8

    def __init__(self, reader, header):
        self._header = header
        self.r_vaddr = reader.read_int()
        self.r_symndx = reader.read_int()

        if header.get_magic() == 'TICOFF2MAGIC':
            self.r_exa = reader.read_short()
        else:
            self.r_exa = 0

        self.r_type = reader.read_short()

    def sizeof(self):
        if self._header.get_magic() in ['TICOFF1MAGIC', 'TICOFF2MAGIC']:
            return CoffRelocation.SIZEOF2
        else:
            return CoffRelocation.SIZEOF

    @property
    def address(self):
        return self.r_vaddr

    @property
    def symbol_index(self):
        return self.r_symndx

    @property
    def extended_address(self):
        return self.r_exa

    @property
    def type(self):
        return self.r_type

    def to_data_type(self):
        struct = {'r_vaddr': 'I', 'r_symndx': 'I'}
        if self._header.get_magic() in ['TICOFF1MAGIC', 'TICOFF2MAGIC']:
            struct['r_exa'] = 'H'
        else:
            struct['r_exa'] = 0
        struct['r_type'] = 'H'

        return {'name': 'CoffRelocation', **struct}
```

Please note that this is a direct translation of the given Java code into Python. The original code seems to be part of an executable file format parser, and it's not clear what exactly each piece of code does without more context or documentation.