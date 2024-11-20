class ISO9660Header:
    def __init__(self):
        self.volume_descriptor_set = []
        self.type_l_index_size_table = {}
        self.type_m_index_size_table = {}
        self.suppl_type_l_index_size_table = {}
        self.suppl_type_m_index_size_table = {}

        self.directory = None
        self.primary_desc = None

    def read_from_binary_reader(self, reader):
        while True:
            type = reader.read_next_byte()
            if type == 0:  # VOLUME_DESC_SET_TERMINATOR
                break
            elif type == 1:  # VOLUME_DESC_BOOT_RECORD
                volume_descriptor_set.append(ISO9660BootRecordVolumeDescriptor(reader))
            elif type == 2:  # VOLUME_DESC_PRIMARY_VOLUME_DESC
                self.primary_desc = ISO9660VolumeDescriptor(reader)
                directory = self.primary_desc.get_directory_entry()
                if directory.is_padding_field_present():
                    reader.set_pointer_index(reader.get_pointer_index() - 1)
            elif type == 3:  # VOLUME_DESC_SUPPL_Volume_DESC
                suppl_desc = ISO9660VolumeDescriptor(reader)
                volume_descriptor_set.append(suppl_desc)

    def get_primary_directory(self):
        return self.directory

    def get_volume_descriptor_set(self):
        return self.volume_descriptor_set

    def get_type_l_index_size_table(self):
        return self.type_l_index_size_table

    def get_type_m_index_size_table(self):
        return self.type_m_index_size_table

    def get_suppl_type_l_index_size_table(self):
        return self.suppl_type_l_index_size_table

    def get_suppl_type_m_index_size_table(self):
        return self.suppl_type_m_index_size_table

    def get_primary_volume_descriptor(self):
        return self.primary_desc

    def __str__(self):
        buff = ""
        for volume in self.volume_descriptor_set:
            buff += str(volume) + "\n"
        return buff

class ISO9660VolumeDescriptor:
    pass  # You would need to implement this class based on the Java equivalent.

# Usage
header = ISO9660Header()
reader = BinaryReader()  # Assuming you have a binary reader implemented.
header.read_from_binary_reader(reader)
print(header.get_primary_directory())
