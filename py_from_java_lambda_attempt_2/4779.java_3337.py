Here is the translation of the given Java code into equivalent Python:

```Python
class NList:
    def __init__(self):
        self.n_strx = None
        self.n_type = None
        self.n_sect = None
        self.n_desc = None
        self.n_value = None
        self.string = None
        self.is32bit = False

    @classmethod
    def create_nlist(cls, reader, is32bit):
        n_list = cls()
        n_list.init_nlist(reader, is32bit)
        return n_list

    def init_nlist(self, reader, is32bit):
        self.is32bit = is32bit
        if isinstance(reader, bytes):  # assuming 'reader' is a byte stream
            self.n_strx = int.from_bytes(reader.read(4), "little")
            self.n_type = reader.read(1)[0]
            self.n_sect = reader.read(1)[0]
            self.n_desc = int.from_bytes(reader.read(2), "little")
        if is32bit:
            self.n_value = int.from_bytes(reader.read(4), "little") & 0xffffffff
        else:
            self.n_value = int.from_bytes(reader.read(8), "little")

    def init_string(self, reader, string_table_offset):
        try:
            self.string = reader[string_table_offset + self.n_strx].decode("utf-8")
        except Exception as e:
            self.string = ""

    @property
    def data_type(self):
        if not hasattr(self, "_data_type"):
            struct = {"n_ strx": int,
                      "n_type": bytes,
                      "n_sect": bytes,
                      "n_desc": int}
            if self.is32bit:
                struct["n_value"] = int
            else:
                struct["n_value"] = int
            self._data_type = StructType(struct)
        return self._data_type

    @property
    def string(self):
        return self.__string

    @string.setter
    def string(self, value):
        if isinstance(value, str) or (isinstance(value, bytes) and len(value) > 0):
            self.__string = value
        else:
            raise ValueError("Invalid string")

    def get_string_table_index(self):
        return self.n_strx

    def get_type(self):
        return self.n_type

    def is_type_undefined(self):
        return (self.n_sect == NListConstants.NO_SECT and
                (self.n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_UNDEF)

    def is_type_absolute(self):
        return (self.n_sect == NListConstants.NO_SECT and
                (self.n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_ABS)

    def is_type_prebound_undefined(self):
        return (self.n_sect == NListConstants.NO_SECT and
                (self.n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_PBUD)

    def is_indirect(self):
        return self.n_sect == NListConstants.NO_SECT and \
               (self.n_type & NListConstants.MASK_N_TYPE) == NListConstants.TYPE_N_INDR

    def is_symbolic_debugging(self):
        return (self.n_type & NListConstants.MASK_N_STAB) != 0

    def is_private_external(self):
        return self.n_type & NListConstants.MASK_N_PEXT != 0

    def is_external(self):
        return self.n_type & NListConstants.MASK_N_EXT != 0

    def is_lazy_bind(self):
        return (self.n_desc & NListConstants.REFERENCE_TYPE) != 0

    def is_thumb_symbol(self):
        return (self.n_desc & NListConstants.DESC_N_ARM_THUMB_DEF) != 0

    @property
    def section(self):
        return self.n_sect

    @property
    def description(self):
        return self.n_desc

    @property
    def value(self):
        return self.n_value

    def get_library_ordinal(self):
        if hasattr(self, "n_desc"):
            return ((self.n_desc >> 8) & 0xff)
        else:
            raise AttributeError("NList object has no attribute 'n_desc'")

    def __str__(self):
        return str(self.string)

class StructType:
    def __init__(self, struct):
        self.struct = struct

    @property
    def category_path(self):
        # Assuming you have a CategoryPath class defined elsewhere in your code.
        return CategoryPath(MachConstants.DATA_TYPE_CATEGORY)
```

Please note that Python does not support the exact equivalent of Java's `StructConverter` and `FactoryBundledWithBinaryReader`. I've replaced these with simpler constructs.