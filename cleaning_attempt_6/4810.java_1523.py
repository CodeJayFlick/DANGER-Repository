class DyldCacheHeader:
    def __init__(self):
        self.magic = None
        self.mapping_offset = 0
        self.mapping_count = 0
        self.images_offset = 0
        self.images_count = 0
        self.dyld_base_address = 0
        self.code_signature_offset = 0
        self.code_signature_size = 0
        self.slide_info_offset = 0
        self.slide_info_size = 0
        self.local_symbols_offset = 0
        self.local_symbols_size = 0
        self.uuid = None
        self.cache_type = 0
        self.branch_pools_offset = 0
        self.branch_pools_count = 0
        self.accelerate_info_addr = 0
        self.accelerate_info_size = 0
        self.images_text_offset = 0
        self.images_text_count = 0

    def get_base_address(self):
        return self.dyld_base_address

    def get_magic(self):
        return self.magic

    def get_mapping_infos(self):
        # This method requires the header to have been parsed.
        pass

    def get_images_offset(self):
        return self.images_offset

    def get_images_count(self):
        return self.images_count

    def get_image_infos(self):
        # This method requires the header to have been parsed.
        pass

    @staticmethod
    def to_data_type():
        struct = DataType("dyld_cache_header", 0)
        if (headerType >= 1):
            struct.add(ByteArrayDataType(ASCII, 16, 1), "magic", "e.g. \"dyld_v0 i386\"")
            # ... and so on
        return struct

    def parse_mapping_info(self, log, monitor) -> None:
        if (self.mapping_offset > 0x28):
            for _ in range(self.mapping_count):
                pass

    def parse_image_info(self, log, monitor) -> None:
        if self.images_offset == 0:
            return
        # ... and so on

    @staticmethod
    def markup_header(program: Program, space: AddressSpace, task_monitor: TaskMonitor, message_log: MessageLog) -> None:
        pass

    def parse_from_memory(self, program: Program, address_space: AddressSpace, log: MessageLog, monitor: TaskMonitor) -> None:
        if self.header_type >= 6:
            # ... and so on
