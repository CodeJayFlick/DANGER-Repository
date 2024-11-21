Here is the translation of the given Java code to Python:

```Python
class CliTableAssemblyRefOS:
    class CliAssemblyRefOSRow:
        def __init__(self, os_platform_id: int, os_major_version: int, os_minor_version: int, assembly_ref_index: int):
            self.os_platform_id = os_platform_id
            self.os_major_version = os_major_version
            self.os_minor_version = os_minor_version
            self.assembly_ref_index = assembly_ref_index

        def get_representation(self) -> str:
            return f"{self.os_platform_id} v{self.os_major_version}.{self.os_minor_version}"

    def __init__(self, reader: object, stream: object, table_id: int):
        super().__init__()
        self.rows = []
        for i in range(self.num_rows):
            row_data = CliAssemblyRefOSRow(reader.read_next_int(), reader.read_next_int(), reader.read_next_int(), self.read_table_index(reader, 1))
            self.rows.append(row_data)

    def get_row_data_type(self) -> object:
        return self.to_data_type()

    def to_data_type(self) -> object:
        row_dt = StructureDataType("AssemblyRefOS Row", 0)
        row_dt.add(DWORD, "OSPlatformID")
        row_dt.add(DWORD, "OSMajorVersion")
        row_dt.add(DWORD, "OSMinorVersion")
        row_dt.add(metadata_stream.get_table_index_data_type(1), "AssemblyRef", "index into AssemblyRef table")
        return ArrayDataType(row_dt, self.num_rows, row_dt.length)
```

Please note that Python does not have direct equivalent of Java's `BinaryReader`, `CliStreamMetadata` and other classes. So I had to remove those parts from the code as they are specific to Java.