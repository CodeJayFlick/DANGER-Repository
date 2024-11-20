class ElfLoadAdapter:
    def add_dynamic_types(self, dynamic_type_map):
        for field in self.__class__.get_declared_fields():
            if Modifier.is_static(field.getModifiers()) and isinstance(field.getType(), type) == bool:
                try:
                    elf_dynamic_type = getattr(self, field.getName())
                    name = str(elf_dynamic_type.name)
                    ElfDynamicType.add_dynamic_type(elf_dynamic_type, dynamic_type_map)
                except (DuplicateNameException, AttributeError):
                    Msg.error(self, "Invalid ElfDynamicType({}) defined by {}".format(name, self.__class__.__name__), None)

    def add_program_header_types(self, program_header_type_map):
        for field in self.__class__.get_declared_fields():
            if Modifier.is_static(field.getModifiers()) and isinstance(field.getType(), type) == bool:
                try:
                    elf_program_header_type = getattr(self, field.getName())
                    name = str(elf_program_header_type.name)
                    ElfProgramHeaderType.add_program_header_type(elf_program_header_type, program_header_type_map)
                except (DuplicateNameException, AttributeError):
                    Msg.error(self, "Invalid ElfProgramHeaderType({}) defined by {}".format(name, self.__class__.__name__), None)

    def add_section_header_types(self, section_header_type_map):
        for field in self.__class__.get_declared_fields():
            if Modifier.is_static(field.getModifiers()) and isinstance(field.getType(), type) == bool:
                try:
                    elf_section_header_type = getattr(self, field.getName())
                    name = str(elf_section_header_type.name)
                    ElfSectionHeaderType.add_section_header_type(elf_section_header_type, section_header_type_map)
                except (DuplicateNameException, AttributeError):
                    Msg.error(self, "Invalid ElfSectionHeaderType({}) defined by {}".format(name, self.__class__.__name__), None)

    def get_preferred_segment_address_space(self, elf_load_helper, elf_program_header):
        program = elf_load_helper.get_program()
        if elf_program_header.is_execute():
            return program.getAddressFactory().getDefaultAddressSpace()
        else:
            # segment is not marked execute, use the data space by default
            return program.getLanguage().getDefaultDataSpace()

    def get_preferred_segment_address(self, elf_load_helper, elf_program_header):
        program = elf_load_helper.get_program()
        address_space = self.get_preferred_segment_address_space(elf_load_helper, elf_program_header)
        addr_word_offset = elf_program_header.get_virtual_address()
        if address_space == program.getAddressFactory().getDefaultAddressSpace():
            addr_word_offset += elf_load_helper.getImageBaseWordAdjustmentOffset()
        return address_space.get_truncated_address(addr_word_offset, True)

    def get_default_alignment(self, elf_load_helper):
        program = elf_load_helper.get_program()
        address_space = program.getAddressFactory().getDefaultAddressSpace()
        unit_size = address_space.getAddressableUnitSize()
        if unit_size != 1:
            return unit_size
        else:
            return 8 if elf_load_helper.get_elf_header().is_64_bit() else 4

    def get_preferred_section_address_space(self, elf_load_helper, elf_section_header):
        program = elf_load_helper.get_program()
        if elf_section_header.is_executable():
            return program.getAddressFactory().getDefaultAddressSpace()
        else:
            # segment is not marked execute, use the data space by default
            return program.getLanguage().getDefaultDataSpace()

    def get_preferred_section_address(self, elf_load_helper, elf_section_header):
        program = elf_load_helper.get_program()
        address_space = self.get_preferred_section_address_space(elf_load_helper, elf_section_header)
        addr_word_offset = elf_section_header.get_address()
        if address_space == program.getAddressFactory().getDefaultAddressSpace():
            addr_word_offset += elf_load_helper.getImageBaseWordAdjustmentOffset()
        return address_space.get_truncated_address(addr_word_offset, True)

    def can_handle(self, elf):
        return False

    def process_elf(self, elf_load_helper, monitor):
        pass  # do nothing extra by default

    def process_got_plt(self, elf_load_helper, monitor):
        got_plt_markup = ElfDefaultGotPltMarkup(elf_load_helper)
        got_plt_markup.process(monitor)

    def creating_function(self, elf_load_helper, function_address):
        return function_address

    def calculate_symbol_address(self, elf_load_helper, elf_symbol):
        try:
            if not elf_symbol.is_external():
                # symbol is internal
                pass  # do nothing extra by default
            else:
                # symbol is external and has been assigned a fake memory address in the EXTERNAL memory block.
                return Address(NO_ADDRESS)
        except NoValueException as e:
            Msg.error(self, "Error calculating symbol address", e)

    def evaluate_elf_symbol(self, elf_load_helper, elf_symbol, address, is_external):
        if not is_external:
            # symbol is internal
            pass  # do nothing extra by default
        else:
            # symbol is external and has been assigned a fake memory address in the EXTERNAL memory block.
            return Address(NO_ADDRESS)

    def get_adjusted_load_size(self, elf_program_header):
        return elf_program_header.get_file_size()

    def get_adjusted_memory_size(self, elf_program_header):
        return elf_program_header.get_memory_size()

    def get_linkage_block_alignment(self):
        return 0x1000

    def get_preferred_external_block_size(self):
        return 0x20000

    def get_external_block_reserve_size(self):
        return 0x10000

    def get_adjusted_section_size(self, elf_section_header):
        return elf_section_header.get_size()

    def has_filtered_load_input_stream(self, elf_load_helper, loadable, start):
        return False
