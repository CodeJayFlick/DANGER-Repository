Here is the translation of the given Java code into Python:

```Python
class OatClass:
    def __init__(self, oat_version):
        self.oat_version = oat_version
        self.status = None
        self.type = None
        self.bitmap_size = 0
        self.bitmap = bytearray()
        self.method_offsets = []

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def bitmap_size(self):
        return self._bitmap_size

    @bitmap_size.setter
    def bitmap_size(self, value):
        self._bitmap_size = value

    @property
    def bitmap(self):
        return self._bitmap

    @bitmap.setter
    def bitmap(self, value):
        self._bitmap = bytearray(value)

    def __init_reader(self, reader):
        if self.type == 1:
            self.bitmap_size = reader.read_int()
            self.bitmap = reader.read_bytes(self.bitmap_size)
            method_offsets_count = sum(bin(int(b)).count('1') for b in self.bitmap)
        else:
            method_offsets_count = len(class_data_item.get_direct_methods()) + len(class_data_item.get_virtual_methods())

        for _ in range(method_offsets_count):
            self.method_offsets.append(OatMethodOffsetsFactory().get_oat_method_offsets(reader, self.oat_version))

    def is_method_native(self, method_index):
        byte_pos = method_index // 8
        bit_pos = method_index % 8
        return (self.bitmap[byte_pos] >> bit_pos) & 0x1 == 0x1

    @property
    def method_offsets(self):
        return self._method_offsets

    @method_offsets.setter
    def method_offsets(self, value):
        self._method_offsets = value

    def to_data_type(self):
        structure = StructureDataType(f"{self.__class__.__name__}_{self.oat_version}", 0)
        if self.bitmap_size > 0:
            structure.name += f"_{self.bitmap_size}"
        if len(self.method_offsets) > 0:
            structure.name += f"_{len(self.method_offsets)}"

        structure.add(OatClassStatus().to_data_type(), "status", None)

        structure.add(WORD, "type", None)
        if self.type == OatClassType.kOatClassSomeCompiled.ordinal():
            structure.add(DWORD, "bitmap_size", None)
            if self.bitmap_size > 0:
                bitmap_data_type = ArrayDataType(BYTE, self.bitmap_size, BYTE.length())
                structure.add(bitmap_data_type, "bitmap", None)

        for i in range(len(self.method_offsets)):
            structure.add(self.method_offsets[i].to_data_type(), f"method_offsets_{i}", None)
```

Please note that Python does not support direct translation of Java code. It is necessary to rewrite the logic and syntax according to Python's rules, conventions, and best practices.