class MemorySectionResolver:
    def __init__(self):
        self.program = None
        self.sections = []
        self.sectionMemoryMap = {}
        self.fileLoadMaps = {}

    def add_initialized_memory_section(self, key, file_offset, number_of_bytes, start_address, section_name,
                                        is_readable=True, is_writable=False, is_executable=False, comment=None):
        if not isinstance(key, MemoryLoadable):
            raise TypeError("Key must be an instance of MemoryLoadable")
        self.sections.append(MemorySection(key, True, file_offset, number_of_bytes, start_address, section_name,
                                            is_readable, is_writable, is_executable, comment))

    def add_uninitialized_memory_section(self, key, number_of_bytes, start_address, section_name):
        if not isinstance(key, MemoryLoadable):
            raise TypeError("Key must be an instance of MemoryLoadable")
        self.sections.append(MemorySection(key, False, -1, number_of_bytes, start_address, section_name))

    def get_resolved_load_addresses(self, key):
        return self.sectionMemoryMap.get(key)

    def resolve(self):
        if not isinstance(self.program.memory_blocks, list) or len(self.program.memory_blocks) > 0:
            raise ValueError("Program memory blocks already exist - unsupported")
        file_allocation_map = AddressRangeObjectMap()
        for section in reversed(list(self.sections)):
            self.resolve_section_memory(section, file_allocation_map)
        return

    def resolve_section_memory(self, section):
        if not isinstance(section, MemorySection):
            raise TypeError("section must be an instance of MemorySection")

    def get_memory_conflict_set(self, range_min, range_max):
        physical_address_range = AddressRange(range_min, range_max)

    def reconcile_section_range_overlap(self, min_physical_addr, max_physical_addr, file_offset, range_list):
        if not isinstance(min_physical_addr, Address) or not isinstance(max_physical_addr, Address):
            raise TypeError("min and max must be instances of Address")
