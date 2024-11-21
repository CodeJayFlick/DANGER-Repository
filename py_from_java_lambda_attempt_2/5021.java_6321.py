Here is the translation of the given Java code to Python:

```Python
class CliTableGenericParam:
    class CliGenericParamRow:
        def __init__(self, number: int, flags: int, owner_index: int, name_index: int):
            self.number = number
            self.flags = flags
            self.owner_index = owner_index
            self.name_index = name_index

        def get_representation(self) -> str:
            try:
                owner_rep = f"Owner {get_row_representation_safe(CliIndexTypeOrMethodDef.get_table_name(owner_index), CliIndexTypeOrMethodDef.get_row_index(owner_index))}"
            except InvalidInputException as e:
                owner_rep = hex(owner_index)
            return f"{metadata_stream.get_strings_stream().get_string(name_index)} Owner {owner_rep} Number {self.number} Flags {CliEnumGenericParamAttributes.data_type.getName(self.flags & 0xffff)}"

    def __init__(self, reader: BinaryReader, stream: CliStreamMetadata, table_id: int):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliGenericParamRow(reader.read_next_short(), reader.read_next_short(),
                                     CliIndexTypeOrMethodDef.read_coded_index(reader, stream), self.read_string_index(reader))
            rows.append(row)
            strings.append(row.name_index)
        reader.set_pointer_index(self.reader_offset)

    def get_row_data_type(self) -> StructureDataType:
        row_dt = StructureDataType(CategoryPath(PATH), "GenericParam Row", 0)
        row_dt.add(WORD, "Number", "index of the generic param, numbered left- to-right, from 0")
        row_dt.add(CliEnumGenericParamAttributes.data_type, "Flags", "Bitmask of type GenericParamAttributes")
        row_dt.add(CliIndexTypeOrMethodDef.to_data_type(metadata_stream), "Owner", "TypeOrMethodDef coded index")
        row_dt.add(metadata_stream.get_string_index_data_type(), "Name", "index into String heap, for description only")
        return row_dt
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. Also, the exception handling in Python is different from Java.