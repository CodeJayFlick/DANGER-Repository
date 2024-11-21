Here is the translation of the Java code to Python:
```python
class CliTableDeclSecurity:
    class CliDeclSecurityRow:
        def __init__(self, action: int, parent_index: int, permission_set_index: int):
            self.action = action
            self.parent_index = parent_index
            self.permission_set_index = permission_set_index

        def get_representation(self) -> str:
            try:
                parent_rep = get_row_representation_safe(
                    CliIndexHasDeclSecurity.get_table_name(parent_index),
                    CliIndexHasDeclSecurity.get_row_index(parent_index)
                )
            except InvalidInputException as e:
                parent_rep = hex(parent_index)[2:]
            return f"Action {self.action} Parent {parent_rep} PermissionSet {hex(self.permission_set_index)}"

    def __init__(self, reader: BinaryReader, stream: CliStreamMetadata, table_id: int):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliDeclSecurityRow(
                reader.read_next_short(),
                CliIndexHasDeclSecurity.read_coded_index(reader, stream),
                self.read_blob_index(reader)
            )
            blobs.add(row.permission_set_index)

    def get_row_data_type(self) -> StructureDataType:
        row_dt = StructureDataType(CategoryPath(PATH), "DeclSecurity Row", 0)
        row_dt.add(WORD, "Action", "Points to a System.Security.SecurityAction as described in ISO23271 IV")
        row_dt.add(CliIndexHasDeclSecurity.to_data_type(metadata_stream), "Parent", None)
        row_dt.add(metadata_stream.get_blob_index_data_type(), "PermissionSet", None)
        return row_dt

class InvalidInputException(Exception):
    pass
```
Note that I had to create a separate `InvalidInputException` class in Python, as there is no direct equivalent to Java's `InvalidInputException`. Additionally, some methods and classes (e.g. `CliStreamMetadata`, `BinaryReader`) were not translated, as they are likely specific to the Ghidra framework and would require additional context or implementation details to translate accurately.