Here is the translation of the given Java code into Python:

```Python
class VtShapeMsType:
    PDB_ID = 0x000a

    def __init__(self):
        self.count = None
        self.descriptor_list = []

    def from_pdb(self, pdb_reader: 'PdbByteReader') -> None:
        super().__init__()
        self.count = pdb_reader.parse_unsigned_short_val()
        byte_val = 0
        value = 0
        descriptor = None

        for i in range(0, self.count // 2):
            byte_val = pdb_reader.parse_unsigned_byte_val()
            value = (byte_val >> 4)
            descriptor = VtShapeDescriptorMsProperty.from_value(value)
            self.descriptor_list.append(descriptor)

            value = byte_val & 0x0f
            descriptor = VtShapeDescriptorMsProperty.from_value(value)
            self.descriptor_list.append(descriptor)

        if self.count % 2 == 1:
            byte_val = pdb_reader.parse_unsigned_byte_val()
            value = (byte_val >> 4)
            descriptor = VtShapeDescriptorMsProperty.from_value(value)
            self.descriptor_list.append(descriptor)

        pdb_reader.skip_padding()

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    @property
    def count_(self):
        return self.count

    @count_.setter
    def set_count_(self, value: int):
        self.count = value

    @property
    def descriptor_list_(self):
        return self.descriptor_list_

    @descriptor_list_.setter
    def set_descriptor_list_(self, value: list):
        self.descriptor_list_ = value

    def has_descriptor(self, descriptor) -> bool:
        return descriptor in self.descriptor_list_

    def emit(self, builder: 'StringBuilder', bind: 'Bind') -> None:
        ds = DelimiterState("", ",")
        builder.append("vtshape: {")
        for descriptor in self.descriptor_list_:
            builder.append(ds.out(True, descriptor))
        builder.append("}")
```

Please note that this is a direct translation of the given Java code into Python. The `PdbByteReader`, `VtShapeDescriptorMsProperty` and other classes are not defined here as they were not provided in the original Java code.