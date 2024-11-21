class CliTableFile:
    class CliFileRow:
        def __init__(self, flags: int, name_index: int, hash_index: int):
            self.flags = flags
            self.name_index = name_index
            self.hash_index = hash_index

        def get_representation(self) -> str:
            hash_rep = f"Index {hash_index:x}"  # TODO: Make this reflect the blob contents (encoded hash? byte array?)
            return f"{metadata_stream.get_string(name_index)} Hash {hash_rep} Flags {CliEnumFileAttributes.data_type.name[flags & 0xffffffff]}"

    def __init__(self, reader: BinaryReader, stream: CliStreamMetadata, table_id: int):
        super().__init__(reader, stream, table_id)
        for i in range(self.num_rows):
            row = CliFileRow(reader.read_next_int(), self.read_string_index(reader), self.read_blob_index(reader))
            rows.append(row)
            strings.append(row.name_index)
            blobs.append(row.hash_index)
        reader.set_pointer_index(self.reader_offset)

    def get_row_data_type(self) -> StructureDataType:
        row_dt = StructureDataType(CategoryPath(PATH), "File Row", 0)
        row_dt.add(CliEnumFileAttributes.data_type, "Flags", "Bitmask of type FileAttributes")
        row_dt.add(metadata_stream.get_string_index_data_type(), "Name", "index into String heap")
        row_dt.add(metadata_stream.get_blob_index_data_type(), "Hash", "index into Blob heap")
        return row_dt
