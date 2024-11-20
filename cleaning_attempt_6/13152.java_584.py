class HCS12X_ElfExtension:
    # Elf Program Header Extensions
    PT_HCS12_ARCHEXT = {"type": 0x70000000, "name": "PT_{}HCS12X_ARCHEXT".format("AH"), "description": "HCS12X extension"}

    SHT_HCS12_ATTRIBUTES = {"type": 0x70000003, "name": "SHT_AHCS12_ATTRIBUTES", "description": "Attribute section"}

    def can_handle(self, elf):
        return elf.e_machine() == ElfConstants.EM_68HC12

    def can_handle_load_helper(self, elf_load_helper):
        language = elf_load_helper.get_program().get_language()
        return self.can_handle(elf_load_helper.get_elf_header()) and "HCS12".lower() in str(language.get_processor()).lower()

    def get_data_type_suffix(self):
        return "_{}HCS12".format("AH")

    def get_preferred_segment_address(self, elf_load_helper, elf_program_header):
        space = self.get_preferred_segment_address_space(elf_load_helper, elf_program_header)
        program = elf_load_helper.get_program()
        addr_word_offset = elf_program_header.virtual_address
        if space == program.address_factory.default_address_space:
            addr_word_offset += elf_load_helper.image_base_word_adjustment_offset
        addr_word_offset = self.hcs12_translate_paged_address(addr_word_offset)
        return space.truncated_address(addr_word_offset, True)

    def get_preferred_section_address(self, elf_load_helper, elf_section_header):
        program = elf_load_helper.get_program()
        space = self.get_preferred_section_address_space(elf_load_helper, elf_section_header)
        addr_word_offset = elf_section_header.address
        if space == program.address_factory.default_address_space:
            addr_word_offset += elf_load_helper.image_base_word_adjustment_offset
        addr_word_offset = self.hcs12_translate_paged_address(addr_word_offset)
        return space.truncated_address(addr_word_offset, True)

    def hcs12_translate_paged_address(self, addr_word_offset):
        page = (addr_word_offset >> 16) & 0xff
        addr = addr_word_offset & 0xffff

        if (addr & 0xfC00) == 0x0:
            return addr
        elif (addr & 0xfc00) == 0x800:
            return 0x100000 | ((page << 10) | (addr & 0x3ff))
        elif (addr & 0xc00) == 0xC00:
            return (0x4FF << 10) | (addr & 0x3ff)
        elif (addr & 0xf000) == 0x1000:
            return (page << 12) | (addr & 0xfff)
        elif (addr & 0xf000) == 0x2000:
            return (0xFE << 12) | (addr & 0xfff)
        elif (addr & 0xf000) == 0x3000:
            return (0xFF << 12) | (addr & 0xfff)
        elif (addr & 0xc00) == 0x4000:
            return 0x400000 | ((0xFD << 14) | (addr & 0x3fff))
        elif (addr & 0xc00) == 0x8000:
            return 0x400000 | ((page << 14) | (addr & 0x3fff))
        elif (addr & 0xc00) == 0xC00:
            return 0x400000 | ((0xFF << 14) | (addr & 0x3fff))

    def evaluate_elf_symbol(self, elf_load_helper, elf_symbol, address, is_external):
        if is_external:
            return address
        sym_name = elf_symbol.name_as_string()
        l_addr = address.offset
        l_addr = self.hcs12_translate_paged_address(l_addr)
        mapped_addr = address.new_address(l_addr)
        return mapped_addr

HCS12X_ElfExtension().evaluate_elf_symbol(None, None, None, False)  # dummy call to ensure the class is defined
