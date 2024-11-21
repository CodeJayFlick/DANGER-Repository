import struct

class ProfileHeader:
    def __init__(self):
        self.magic = None
        self.version = None
        self.number_of_dex_files = 0
        self.uncompressed_size_of_zipped_data = 0
        self.compressed_data_size = 0
        self._compressed_data_offset = 0

    def from_binary_reader(self, reader):
        magic_length = len(ProfileConstants.kProfileMagic)
        version_length = len(ProfileConstants.kProfileVersion_008)

        self.magic = reader.read_next_bytes(magic_length).decode('utf-8').strip()
        self.version = reader.read_next_bytes(version_length).decode('utf-8').strip()

        self.number_of_dex_files = reader.read_next_byte()
        self.uncompressed_size_of_zipped_data = struct.unpack('<i', reader.read_next_bytes(4))[0]
        self.compressed_data_size = struct.unpack('<i', reader.read_next_bytes(4))[0]

    def get_magic(self):
        return self.magic

    def get_version(self):
        return self.version

    def get_number_of_dex_files(self):
        return self.number_of_dex_files

    def get_uncompressed_size_of_zipped_data(self):
        return self.uncompressed_size_of_zipped_data

    def get_compressed_data_size(self):
        return self.compressed_data_size

    def get_compressed_data_offset(self):
        return self._compressed_data_offset
