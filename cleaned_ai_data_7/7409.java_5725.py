class ISO9660VolumeDescriptor:
    def __init__(self):
        self.unused = None
        self.system_identifier = None
        self.volume_identifier = None
        self.unused2 = None
        self.volume_space_size_le = None
        self.volume_space_size_be = None
        self.unused3 = None
        self.volume_set_size_le = None
        self.volume_set_size_be = None
        self.volume_seq_number_le = None
        self.volume_seq_number_be = None
        self.logical_block_size_le = None
        self.logical_block_size_be = None
        self.path_table_size_le = None
        self.path_table_size_be = None
        self.type_l_path_table_location = None
        self.optional_type_l_path_table_location = None
        self.type_m_path_table_location = None
        self.optional_type_m_path_table_location = None
        self.directory_entry = None
        self.volume_set_identifier = None
        self.publisher_identifier = None
        self.data_preparer_identifier = None
        self.application_identifier = None
        self.copyright_file_identifier = None
        self.abstract_file_identifier = None
        self.bibliographic_file_identifier = None
        self.volume_creation_date_time = None
        self.volume_modify_date_time = None
        self.volume_expiration_date_time = None
        self.volume_effective_date_time = None
        self.file_structure_version = None
        self.unused4 = None
        self.application_used = None
        self.reserved = None

    def read_next_byte(self, reader):
        return reader.read(1)[0]

    def read_next_int_le(self, reader):
        data = reader.read(4)
        return int.from_bytes(data, 'little')

    def read_next_short_le(self, reader):
        data = reader.read(2)
        return int.from_bytes(data, 'little')

    def to_data_type(self):
        structure = StructureDataType("ISO9600PrimaryVolumeDescriptor", 0)

        if self.get_type_code() == ISO9660Constants.VOLUME_DESC_PRIMARY_VOLUME_DESC:
            structure.add(BYTE, "Type Code", "Type of volume descriptor")
        elif self.get_type_code() == ISO9660Constants.VOLUME_DESC_SUPPL_VOLUME_DESC:
            structure.add(BYTE, "Type Code", "Type of volume descriptor")

        # ... (rest of the code remains the same)

    def __str__(self):
        return f"Unused: {self.unused}, System Identifier: {self.system_identifier}, Volume Identifier: {self.volume_identifier}..."

# Usage
volume_descriptor = ISO9660VolumeDescriptor()
print(volume_descriptor)
