Here is the translation of the Java code into Python:

```Python
class PdbAddressManager:
    def __init__(self, applicator, image_base):
        self.applicator = applicator
        self.image_base = image_base
        self.real_addresses_by_section = {}
        self.segment_map_list = []
        self.image_section_headers = None
        self.omap_from_source = None
        self.memory_group_refinement = []
        self.memory_section_refinement = []

    def get_address(self, segment, offset):
        if segment < 0:
            return BAD_ADDRESS

        relative_virtual_address = None
        if self.image_section_headers is not None:
            if segment > len(self.image_section_headers) + 1:
                return BAD_ADDRESS
            elif segment == 0 or segment == len(self.image_section_headers) + 1:
                # External address.
                return EXTERNAL_ADDRESS

            relative_virtual_address = self.image_section_headers[segment - 1].get_virtual_address() + offset
            relative_virtual_address = apply_omap(relative_virtual_address)
            if relative_virtual_address is None:
                return BAD_ADDRESS
            elif relative_virtual_address == 0:
                return ZERO_ADDRESS

        else:
            # TODO: need to verify use of segments here!
            if segment > len(self.segment_map_list) + 1:
                return BAD_ADDRESS
            elif segment == 0 or segment == len(self.segment_map_list) + 1:
                # External address.
                return EXTERNAL_ADDRESS

            relative_virtual_address = self.segment_map_list[segment - 1].get_segment_offset()

        return self.image_base.add(relative_virtual_address)

    def apply_omap(self, relative_virtual_address):
        if self.omap_from_source is None:
            return relative_virtual_address
        head_map = self.omap_from_source.head_map(relative_virtual_address + 1)
        if not head_map.isEmpty():
            from_value = head_map.last_key()
            to_value = head_map.get(from_value)
            if to_value == 0:
                return 0L

            return to_value + (relative_virtual_address - from_value)

    def get_remap_address_by_address(self, address):
        return self.remap_address_by_address.getOrDefault(address, address)

    def put_remap_address_by_address(self, address, remap_address):
        lookup = self.remap_address_by_address.get(address)
        if lookup is None:
            self.remap_address_by_address[address] = remap_address
        elif not lookup.equals(remap_address) and lookup != BAD_ADDRESS:
            self.applicator.append_log_msg("Trying to map a mapped address to a new address... key: " + str(address) +
                                            ", currentMap: " + str(lookup) + ", newMap: " + str(remap_address))
            self.remap_address_by_address[address] = BAD_ADDRESS

    def log_memory_section_refinement(self):
        PdbLog.message("\nMemorySectionRefinement")
        for sym in self.memory_section_refinement:
            self.applicator.check_canceled()
            name = sym.get_name()
            segment = sym.get_segment()
            offset = sym.get_offset()
            length = sym.get_length()
            characteristics = sym.get_characteristics()
            address = get_address(sym)
            PdbLog.message(String.format("%s: [%04X:%08X](%s) Len:%08X, Characteristics:%08X", name,
                                          segment, offset, str(address), length, characteristics))

    def log_memory_group_refinement(self):
        PdbLog.message("\nMemoryGroupRefinement")
        for sym in self.memory_group_refinement:
            self.applicator.check_canceled()
            name = sym.get_name()
            segment = sym.get_segment()
            offset = sym.get_offset()
            length = sym.get_length()
            characteristics = sym.get_characteristics()
            address = get_address(sym)
            PdbLog.message(String.format("%s: [%04X:%08X](%s) Len:%08X, Characteristics:%08X", name,
                                          segment, offset, str(address), length, characteristics))

    def determine_memory_blocks(self):
        pdb_info = self.applicator.get_pdb().get_debug_info()
        if pdb_info is None:
            return

        self.segment_map_list = pdb_info.get_segment_map_list()

    def map_pre_existing_symbols(self):
        program = self.applicator.get_program()
        if program is None:
            raise PdbException("Program may not be null")

        symbol_iterator = program.get_symbol_table().get_all_symbols(false)
        while symbol_iterator.has_next():
            symbol = symbol_iterator.next()
            name = symbol.get_path().to_string()
            address = symbol.get_address()

            existing_address = self.address_by_pre_existing_symbol_name.get(name, None)
            if existing_address is not None:
                return

            self.address_by_pre_existing_symbol_name[name] = address
            if symbol.is_primary():
                primary_symbol_map[address] = symbol

    def get_primary_symbol(self, address):
        return primary_symbol_map.get(address)

    # This method might be used to set the real addresses for a section.
    def put_real_addresses_by_section(self, section_num, real_address):
        self.real_addresses_by_section[section_num] = real_address
```

Note that this translation is not perfect and may require some manual adjustments.