class ElfProgramHeader:
    def __init__(self):
        self.header = None
        self.p_type = 0
        self.p_flags = 0
        self.p_offset = 0
        self.p_vaddr = 0
        self.p_paddr = 0
        self.p_filesz = 0
        self.p_memsz = 0
        self.p_align = 0

    @staticmethod
    def create_elf_program_header(reader, header):
        elf_program_header = ElfProgramHeader()
        elf_program_header.init_elf_program_header(reader, header)
        return elf_program_header

    def init_elf_program_header(self, reader, header):
        if isinstance(header, int) and header == 32:
            self.p_type = reader.read_next_int()
            self.p_offset = reader.read_next_int() & 0xFFFFFFFF
            self.p_vaddr = reader.read_next_int() & 0xFFFFFFFF
            self.p_paddr = reader.read_next_int() & 0xFFFFFFFF
            self.p_filesz = reader.read_next_int() & 0xFFFFFFFF
            self.p_memsz = reader.read_next_int() & 0xFFFFFFFF
            self.p_flags = reader.read_next_int()
            self.p_align = reader.read_next_int() & 0xFFFFFFFF
        elif isinstance(header, int) and header == 64:
            self.p_type = reader.read_next_int()
            self.p_flags = reader.read_next_int()
            self.p_offset = reader.read_next_long()
            self.p_vaddr = reader.read_next_long()
            self.p_paddr = reader.read_next_long()
            self.p_filesz = reader.read_next_long()
            self.p_memsz = reader.read_next_long()
            self.p_align = reader.read_next_long()

    def get_type_as_string(self):
        if isinstance(self.header, int) and self.header == 32:
            return "PT_0x" + format(self.p_type, '08X')
        elif isinstance(self.header, int) and self.header == 64:
            return str(ElfProgramHeaderType(self.p_type).name)

    def get_description(self):
        if isinstance(self.header, int) and self.header == 32:
            return "PT_0x" + format(self.p_type, '08X')
        elif isinstance(self.header, int) and self.header == 64:
            return str(ElfProgramHeaderType(self.p_type).description)

    def get_comment(self):
        if isinstance(self.header, int) and self.header == 32:
            return "PT_0x" + format(self.p_type, '08X') + " - " + self.get_description()
        elif isinstance(self.header, int) and self.header == 64:
            return str(ElfProgramHeaderType(self.p_type).name)

    def get_align(self):
        return self.p_align

    def get_file_size(self):
        return self.p_filesz

    def get_flags(self):
        return self.p_flags

    def is_read(self):
        if isinstance(self.header, int) and self.header == 32:
            return True
        elif isinstance(self.header, int) and self.header == 64:
            return False

    def is_write(self):
        if isinstance(self.header, int) and self.header == 32:
            return True
        elif isinstance(self.header, int) and self.header == 64:
            return False

    def is_execute(self):
        if isinstance(self.header, int) and self.header == 32:
            return True
        elif isinstance(self.header, int) and self.header == 64:
            return False

    def get_memory_size(self):
        return self.p_memsz

    def get_adjusted_memory_size(self):
        # This is not implemented in the original Java code.
        pass

    def get_adjusted_load_size(self):
        # This is not implemented in the original Java code.
        pass

    def get_reader(self):
        return self.reader

    def set_offset(self, offset):
        self.p_offset = offset

    def set_size(self, file_size, mem_size):
        self.p_filesz = file_size
        self.p_memsz = mem_size

    def get_physical_address(self):
        if isinstance(self.header, int) and self.header == 32:
            return self.p_paddr & 0xFFFFFFFF
        elif isinstance(self.header, int) and self.header == 64:
            return self.p_paddr

    def get_virtual_address(self):
        if isinstance(self.header, int) and self.header == 32:
            return self.p_vaddr & 0xFFFFFFFF
        elif isinstance(self.header, int) and self.header == 64:
            return self.p_vaddr

    def to_data_type(self):
        dt_name = "Elf" + str(4 if isinstance(self.header, int) and self.header == 32 else 8)
        struct = {"p_type": DWORD, "p_offset": QWORD, "p_vaddr": QWORD, "p_paddr": QWORD,
                  "p_filesz": QWORD, "p_memsz": QWORD, "p_flags": DWORD, "p_align": QWORD}
        return dt_name

    def set_address(self, paddr, vaddr):
        self.p_paddr = paddr
        self.p_vaddr = vaddr

    def __eq__(self, other):
        if not isinstance(other, ElfProgramHeader):
            return False
        return (isinstance(self.header, int) and isinstance(other.header, int)) \
               and self.reader == other.reader \
               and self.p_type == other.p_type \
               and self.p_flags == other.p_flags \
               and self.p_offset == other.p_offset \
               and self.p_vaddr == other.p_vaddr \
               and self.p_paddr == other.p_paddr \
               and self.p_filesz == other.p_filesz \
               and self.p_memsz == other.p_memsz

    def __lt__(self, other):
        if not isinstance(other, ElfProgramHeader):
            return False
        return (isinstance(self.header, int) and isinstance(other.header, int)) \
               and self.p_vaddr < other.p_vaddr

    def __hash__(self):
        return hash((self.reader, self.p_type, self.p_flags, self.p_offset))
