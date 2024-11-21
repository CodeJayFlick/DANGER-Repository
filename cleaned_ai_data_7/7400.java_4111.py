class ISO9660BaseVolume:
    def __init__(self):
        self.volume_index = None
        self.type_code = None
        self.identifier = None
        self.version = None

    def from_binary_reader(self, reader):
        try:
            self.volume_index = reader.get_pointer_index()
            self.type_code = reader.read_next_byte()
            self.identifier = reader.read_next_bytes(ISO9660Constants.MAGIC_BYTES_LENGTH)
            self.version = reader.read_next_byte()
        except Exception as e:
            print(f"Error: {e}")

    def to_data_type(self):
        structure = {"Type Code": {"type": "byte", "value": self.type_code},
                     "Standard Identifier": {"type": "bytes", "value": self.identifier},
                     "Version": {"type": "byte", "value": self.version}}
        return structure

    def __str__(self):
        string_buffer = ""
        if self.volume_index is not None:
            string_buffer += f"Volume Index: {self.volume_index}\n"
        if self.type_code is not None:
            string_buffer += f"Type Code: 0x{int(self.type_code):X} => {self.get_type_code_string()}\n"
        if self.identifier is not None:
            string_buffer += f"Standard Identifier: {''.join(map(str, self.identifier))}\n"
        if self.version is not None:
            string_buffer += f"Version: 0x{int(self.version):X}\n"

        return string_buffer

    def get_type_code_string(self):
        type_codes = {
            ISO9660Constants.VOLUME_DESC_BOOT_RECORD: "Boot Record",
            ISO9660Constants.VOLUME_DESC_PRIMARY_VOLUME_DESC: "Primary Volume Descriptor",
            ISO9660Constants.VOLUME_DESC_SUPPL_VOLUME_DESC: "Supplementary Volume Descriptor",
            ISO9660Constants.VOLUME_PARTITION_DESC: "Volume Partition Descriptor",
            ISO9660Constants.VOLUME_DESC_SET_TERMINATOR: "Volume Descriptor Set Terminator"
        }
        return type_codes.get(self.type_code, "")

    def get_type_code(self):
        return self.type_code

    def get_identifier(self):
        return self.identifier

    def get_version(self):
        return self.version

    def get_volume_index(self):
        return self.volume_index
