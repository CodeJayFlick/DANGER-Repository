class CliTableAssembly:
    class CliAssemblyRow:
        def __init__(self, hash_alg, major_version, minor_version, build_number, revision_number, flags, public_key_index, name_index, culture_index):
            self.hash_alg = hash_alg
            self.major_version = major_version
            self.minor_version = minor_version
            self.build_number = build_number
            self.revision_number = revision_number
            self.flags = flags
            self.public_key_index = public_key_index
            self.name_index = name_index
            self.culture_index = culture_index

        def get_representation(self):
            return f"{self.metadata_stream.get_strings_stream().get_string(self.name_index)} v{self.major_version}.{self.minor_version} build{self.build_number} rev{self.revision_number} pubkey index {self.public_key_index} culture index {self.culture_index} flags {CliEnumAssemblyFlags.get_name(self.flags & 0xffffffff)}"

    def __init__(self, reader, stream, table_id):
        super().__init__(reader, stream, table_id)
        self.row_dt = self.to_data_type()
        for i in range(self.num_rows):
            reader.set_pointer_index(self.reader_offset + self.row_dt.get_length() * i)
            row = CliAssemblyRow(reader.read_next_int(), reader.read_next_short(), reader.read_next_short(),
                                  reader.read_next_short(), reader.read_next_short(), reader.read_next_int(),
                                  self.read_blob_index(reader), self.read_string_index(reader),
                                  self.read_string_index(reader))
            self.rows.append(row)
            self.blobs.append(row.public_key_index)
            self.strings.append(row.name_index)
            self.strings.append(row.culture_index)

        reader.set_pointer_index(self.reader_offset)

    def get_row_data_type(self):
        return self.to_data_type()

    @staticmethod
    def markup(program, is_binary, monitor, log, nt_header):
        for row in rows:
            assembly_row = CliAssemblyRow(row)
            if assembly_row.public_key_index > 0:
                sig_addr = CliAbstractStream.get_stream_markup_address(
                    program, is_binary, monitor, log, nt_header,
                    metadata_stream.get_blob_stream(), assembly_row.public_key_index
                )
                assembly_sig = CliSigAssembly(metadata_stream.get_blob_stream().get_blob(assembly_row.public_key_index))
                metadata_stream.get_blob_stream().update_blob(assembly_sig, sig_addr, program)

    @staticmethod
    def to_data_type():
        table = StructureDataType(CategoryPath(PATH), "Assembly Table", 0)
        table.add(CliEnumAssemblyHashAlgorithm.data_type, "HashAlg", "Type of hash present")
        table.add(WORD, "MajorVersion", None)
        table.add(WORD, "MinorVersion", None)
        table.add(WORD, "BuildNumber", None)
        table.add(WORD, "RevisionNumber", None)
        table.add(CliEnumAssemblyFlags.data_type, "Flags", "Bitmask of type AssemblyFlags")
        table.add(metadata_stream.get_blob_index_data_type(), "PublicKey", "index into Blob heap")
        table.add(metadata_stream.get_string_index_data_type(), "Name", "index into String heap")
        table.add(metadata_stream.get_string_index_data_type(), "Culture", "index into String heap")
        return table
