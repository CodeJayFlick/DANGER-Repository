Here is the translation of the given Java code into Python:

```Python
class VirtualFunctionTableMsType:
    PDB_ID = 0x151d

    def __init__(self):
        self.owner_record_number = None
        self.base_virtual_function_table_record_number = None
        self.vfptr_offset_rel_to_object_layout = None
        self.names_array_length = None
        self.vftable_name = None
        self.names = []

    @classmethod
    def from_pdb_reader(cls, pdb, reader):
        instance = cls()
        super().__init__(pdb, reader)
        instance.owner_record_number = RecordNumber.parse(pdb, reader, 32)
        instance.base_virtual_function_table_record_number = \
            RecordNumber.parse(pdb, reader, 32)
        instance.vfptr_offset_rel_to_object_layout = reader.read_int()
        instance.names_array_length = reader.read_int()
        names_reader = reader.get_sub_pdb_byte_reader(instance.names_array_length)
        first = True
        while names_reader.has_more():
            name = names_reader.parse_null_terminated_string(pdb.get_one_byte_charset())
            if first:
                first = False
                instance.vftable_name = name
            else:
                instance.names.append(name)
        reader.skip_padding()
        return instance

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder, bind):
        builder.append("VFTable for [")
        builder.append(pdb.get_type_record(self.owner_record_number))
        builder.append("<vfptr_offset=" + str(self.vfptr_offset_rel_to_object_layout) + ">")
        if self.base_virtual_function_table_record_number != RecordNumber.NO_TYPE:
            builder.append("  : ")
            builder.append(pdb.get_type_record(self.base_virtual_function_table_record_number))
        builder.append("] " + self.vftable_name)
        builder.append(": {")

        delimiter_state = DelimiterState("", ",")
        for name in self.names:
            builder.append(delimiter_state.out(True, name))  # Method names.
        builder.append("}")
```

Note: This Python code assumes that the following classes and methods are defined elsewhere:

- `RecordNumber`
- `PdbByteReader`
- `AbstractPdb`
- `DelimiterState`