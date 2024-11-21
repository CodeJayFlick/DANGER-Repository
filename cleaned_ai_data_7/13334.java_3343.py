class PIC30ElfRelocationContext:
    def __init__(self, handler, load_helper, relocation_table, symbol_map):
        super().__init__(handler, load_helper, relocation_table, symbol_map)

    @staticmethod
    def is_debug_section(overlay_space):
        name = overlay_space.name
        return name.startswith(".debug_") or name == ".comment"

    def get_relocation_address(self, base_address, reloc_offset):
        if not base_address.is_loaded_memory_address() and self.is_debug_section(base_address.address_space):
            reloc_offset >>= 1
        return base_address.add_wrap(reloc_offset)
