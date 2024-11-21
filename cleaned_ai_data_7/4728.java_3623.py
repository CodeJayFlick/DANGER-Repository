class ElfSectionHeader:
    def __init__(self):
        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None

    @staticmethod
    def create_elf_section_header(reader, header):
        elf_section_header = ElfSectionHeader()
        elf_section_header.init_elf_section_header(reader, header)
        return elf_section_header

    def init_elf_section_header(self, reader, header):
        self.reader = reader
        self.header = header

        if isinstance(header, int) and 32 == header:
            sh_type = 'Elf32'
        elif isinstance(header, int) and 64 == header:
            sh_type = 'Elf64'

        if sh_type == 'Elf32':
            self.sh_name = reader.read_next_int()
            self.sh_type = reader.read_next_int()

            self.sh_flags = reader.read_next_int() & Conv.INT_MASK
            self.sh_addr = reader.read_next_int() & Conv.INT_MASK
            self.sh_offset = reader.read_next_int() & Conv.INT_MASK
            self.sh_size = reader.read_next_int() & Conv.INT_MASK

        elif sh_type == 'Elf64':
            self.sh_name = reader.read_next_long()
            self.sh_type = reader.read_next_long()

            self.sh_flags = reader.read_next_long()
            self.sh_addr = reader.read_next_long()
            self.sh_offset = reader.read_next_long()
            self.sh_size = reader.read_next_long()

        self.sh_link = reader.read_next_int()
        self.sh_info = reader.read_next_int()

    def get_elf_header(self):
        return self.header

    def write(self, raf, dc) -> None:
        if isinstance(self.header, int) and 32 == self.header:
            raf.write(dc.get_bytes(self.sh_name))
            raf.write(dc.get_bytes(self.sh_type))

            if sh_type == 'Elf32':
                raf.write(dc.get_bytes((int)(self.sh_flags)))
                raf.write(dc.get_bytes((int)(self.sh_addr)))
                raf.write(dc.get_bytes((int)(self.sh_offset)))
                raf.write(dc.get_bytes((int)(self.sh_size)))

            elif sh_type == 'Elf64':
                raf.write(dc.get_bytes(self.sh_flags))
                raf.write(dc.get_bytes(self.sh_addr))
                raf.write(dc.get_bytes(self.sh_offset))
                raf.write(dc.get_bytes(self.sh_size))

        self.sh_link = reader.read_next_int()
        self.sh_info = reader.read_next_int()

    def get_address(self):
        return self.header.adjust_address_for_prelink(self.sh_addr)

    def get_address_alignment(self):
        return self.sh_addralign

    def get_entry_size(self):
        return self.sh_entsize

    def get_flags(self):
        return self.sh_flags

    def is_writable(self) -> bool:
        if isinstance(self.header, int) and 32 == self.header:
            return header.get_load_adapter().is_section_writable(self)
        elif isinstance(self.header, int) and 64 == self.header:
            return header.get_load_adapter().is_section_writable(self)

    def is_executable(self) -> bool:
        if isinstance(self.header, int) and 32 == self.header:
            return header.get_load_adapter().is_section_executable(self)
        elif isinstance(self.header, int) and 64 == self.header:
            return header.get_load_adapter().is_section_executable(self)

    def is_alloc(self) -> bool:
        if isinstance(self.header, int) and 32 == self.header:
            return header.get_load_adapter().is_section_allocated(self)
        elif isinstance(self.header, int) and 64 == self.header:
            return header.get_load_adapter().is_section_allocated(self)

    def get_info(self):
        return self.sh_info

    def get_link(self):
        return self.sh_link

    def update_name(self):
        if reader is None:
            raise UnsupportedOperationException("This ElfSectionHeader does not have a reader")

        sections = self.header.get_sections()
        e_shstrndx = self.header.e_shstrndx()

        name = None
        try:
            if sh_name >= 0 and e_shstrndx >= 0 and e_shstrndx < len(sections):
                string_table_offset = sections[e_shstrndx].get_offset()
                if string_table_offset >= 0:
                    offset = string_table_offset + self.sh_name
                    if offset < reader.length():
                        name = reader.read_ascii_string(string_table_offset + self.sh_name)
                        if "" == name:
                            name = None

        except IOException as e:
            # ignore
            pass

        if name is None:
            name = "NO-NAME"
            for i in range(len(sections)):
                if sections[i] == this:
                    name = f"SECTION{i}"
                    break

    def get_name_as_string(self):
        return self.name

    def __str__(self) -> str:
        return f"{name} - 0x{Long.toHexString(self.sh_addr)}:0x{Long.toHexString(self.sh_addr + self.sh_size - 1)}"

    def get_offset(self):
        return self.sh_offset

    def set_offset(self, offset):
        if isinstance(self.header, int) and 32 == self.header:
            raise UnsupportedOperationException("Attempting to place non-loaded section into memory:" + name)
        elif isinstance(self.header, int) and 64 == self.header:
            pass
        self.sh_addr = self.header.unadjust_address_for_prelink(offset)

    def set_name(self, name):
        self.name = name

    @staticmethod
    def to_data_type():
        dtName = "Elf32_Shdr" if isinstance(header, int) and 32 == header else "Elf64_Shdr"
        struct = StructureDataType(new CategoryPath("/ELF"), dtName, 0)
        struct.add(DWORD, "sh_name", None)
        struct.add(get_type_data_type(), "sh_type", None)

    def get_type_data_type():
        if isinstance(header, int) and 32 == header:
            return DWordDataType.dataType
        elif isinstance(header, int) and 64 == header:
            return QWORD

    @staticmethod
    def from_data_type(dt):
        pass

    def __eq__(self, other):
        if not (isinstance(other, ElfSectionHeader)):
            return False
        reader = self.reader
        sh_name = self.sh_name
        sh_type = self.sh_type
        sh_flags = self.sh_flags
        sh_addr = self.sh_addr
        sh_offset = self.sh_offset
        sh_size = self.sh_size
        sh_link = self.sh_link
        sh_info = self.sh_info

    def __hash__(self):
        return (int)((17 * self.sh_offset) + (self.sh_offset >> 32))
