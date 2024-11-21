class ResourceDirectory:
    NAME = "IMAGE_RESOURCE_DIRECTORY"
    SIZEOF = 16

    def __init__(self):
        self.characteristics = None
        self.time_data_stamp = None
        self.major_version = None
        self.minor_version = None
        self.number_of_named_entries = None
        self.number_of_id_entries = None
        self.entries = []

    def from_binary_reader(self, reader, index, resource_base, is_first_level, nt_header):
        if not nt_header.check_pointer(index):
            print("Invalid file index", hex(index))
            return

        if ResourceDataDirectory.directory_map.contains(index):
            print("Duplicate ResourceDirectory at", hex(index), "ignored.")
            return
        ResourceDataDirectory.directory_map.add(index)

        self.characteristics = reader.read_int(index); index += 4
        self.time_data_stamp = reader.read_int(index); index += 4
        self.major_version = reader.read_short(index); index += 2
        self.minor_version = reader.read_short(index); index += 2
        self.number_of_named_entries = reader.read_short(index); index += 2
        self.number_of_id_entries = reader.read_short(index); index += 2

        rva = index + (self.number_of_named_entries + self.number_of_id_entries) * ResourceDataDirectory.IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY
        if not nt_header.check_rva(rva) or (rva > 0 and rva > len(reader)):
            print("Too many resource entries", self.number_of_named_entries + self.number_of_id_entries)
            self.number_of_named_entries = self.number_of_id_entries = 0

        for i in range(self.number_of_named_entries):
            if not nt_header.check_pointer(index):
                print("Invalid file index", hex(index))
                return
            entry = ResourceDirectoryEntry(reader, index, resource_base, True, is_first_level, nt_header)
            if not entry.is_valid():
                return
            self.entries.append(entry); index += 8

        for i in range(self.number_of_id_entries):
            if not nt_header.check_pointer(index):
                print("Invalid file index", hex(index))
                return
            entry = ResourceDirectoryEntry(reader, index, resource_base, False, is_first_level, nt_header)
            if not entry.is_valid():
                return
            self.entries.append(entry); index += 8

    def get_entries(self):
        return self.entries[:]

class ResourceDirectoryEntry:
    pass

ResourceDataDirectory = None
