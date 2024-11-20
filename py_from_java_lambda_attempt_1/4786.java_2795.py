Here is the translation of the Java code into Python:

```Python
class SegmentCommand:
    def __init__(self):
        self.segname = None
        self.vmaddr = 0
        self.vmsize = 0
        self.fileoff = 0
        self.filesize = 0
        self.maxprot = 0
        self.initprot = 0
        self.nsects = 0
        self.flags = 0
        self.is32bit = False
        self.sections = []

    @classmethod
    def create_segment_command(cls, reader, is_32_bit):
        segment_command = cls()
        segment_command.init_segment_command(reader, is_32_bit)
        return segment_command

    def init_segment_command(self, reader, is_32_bit):
        if not isinstance(is_32_bit, bool):
            raise TypeError("is_32_bit must be a boolean")

        self.is32bit = is_32_bit
        self.segname = reader.read_next_ascii_string(MachConstants.NAME_LENGTH)
        if is_32_bit:
            self.vmaddr = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')
            self.vmsize = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')
            self.fileoff = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')
            self.filesize = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')
        else:
            self.vmaddr = reader.read_next_long()
            self.vmsize = reader.read_next_long()
            self.fileoff = reader.read_next_long()
            self.filesize = reader.read_next_long()

        self.maxprot = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')
        self.initprot = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')
        self.nsects = int.from_bytes(reader.read_next_int().to_bytes(4, 'little'), byteorder='little')

        for _ in range(self.nsects):
            section = Section.create_section(reader, is_32_bit)
            self.sections.append(section)

    def get_sections(self):
        return self.sections

    def get_section_containing(self, address):
        offset = int(address.get_offset())
        for section in self.sections:
            start = int(section.get_address())
            end = start + int(section.get_size())
            if offset >= start and offset <= end:
                return section
        return None

    def get_section_by_name(self, name):
        for section in self.sections:
            if section.get_section_name().lower() == name.lower():
                return section
        return None

    def get_segment_name(self):
        return self.segname

    def get_vm_address(self):
        return self.vmaddr

    def get_vm_size(self):
        return self.vmsize

    def get_file_offset(self):
        return self.fileoff

    def set_file_offset(self, fileoffset):
        self.fileoff = int(fileoffset)

    def get_file_size(self):
        return self.filesize

    def is_read_protected(self):
        return (self.initprot & SegmentConstants.PROTECTION_R) != 0

    def is_write_protected(self):
        return (self.initprot & SegmentConstants.PROTECTION_W) != 0

    def is_execute_protected(self):
        return (self.initprot & SegmentConstants.PROTECTION_X) != 0

    def get_number_of_sections(self):
        return self.nsects

    def get_flags(self):
        return self.flags

    def is_apple_protected(self):
        return (self.flags & SegmentConstants.FLAG_APPLE_PROTECTED) != 0

    @classmethod
    def to_data_type(cls, reader, is_32_bit):
        if not isinstance(is_32_bit, bool):
            raise TypeError("is_32_bit must be a boolean")

        struct = StructureDataType()
        struct.add(DWORD(), "cmd", None)
        struct.add(DWORD(), "cmdsize", None)
        struct.add(StringDataType(MachConstants.NAME_LENGTH), "segname", None)

        if is_32_bit:
            struct.add(DWORD(), "vmaddr", None)
            struct.add(DWORD(), "vmsize", None)
            struct.add(DWORD(), "fileoff", None)
            struct.add(DWORD(), "filesize", None)
        else:
            struct.add(QWORD(), "vmaddr", None)
            struct.add(QWORD(), "vmsize", None)
            struct.add(QWORD(), "fileoff", None)
            struct.add(QWORD(), "filesize", None)

        struct.add(DWORD(), "maxprot", None)
        struct.add(DWORD(), "initprot", None)
        struct.add(DWORD(), "nsects", None)
        struct.add(DWORD(), "flags", None)

        return struct

    def get_command_name(self):
        return "segment_command"

class StructureDataType:
    pass
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The `StructureDataType` class in the original Java code seems to have been removed from the translated Python code as there was no equivalent data type available in Python at the time of writing.