class ArtMethod:
    def __init__(self, reader, pointer_size, art_version):
        self.pointer_size = pointer_size
        self.art_version = art_version
        
        if (art_version == "MARSHMALLOW_RELEASE" or 
            art_version == "NOUGAT_RELEASE" or 
            art_version == "NOUGAT_MR2_PIXEL_RELEASE"):
            if pointer_size == 4:
                self.declaring_class = reader.read_int()
                self.dex_cache_resolved_methods = int.from_bytes(reader.read(4), 'little')
                self.dex_cache_resolved_types = int.from_bytes(reader.read(4), 'little')
                self.access_flags = reader.read_int()
                self.dex_code_item_offset = reader.read_int()
                self.dex_method_index = reader.read_int()
                self.method_index = reader.read_short()
                self.hotness_count = reader.read_short()
            elif pointer_size == 8:
                self.declaring_class = reader.read_int()
                self.access_flags = reader.read_int()
                self.dex_code_item_offset = reader.read_int()
                self.dex_method_index = reader.read_int()
                self.method_index = reader.read_short()
                self.hotness_count = reader.read_short()
                self.imt_index = reader.read_short()
                self.padding = reader.read_short()

        elif art_version == "OREO_RELEASE" or \
             art_version == "OREO_DR1_RELEASE" or \
             art_version == "OREO_MR1_RELEASE":
            if pointer_size == 4:
                self.declaring_class = reader.read_int()
                self.access_flags = reader.read_int()
                self.dex_code_item_offset = reader.read_int()
                self.dex_method_index = reader.read_int()
                self.method_index = reader.read_short()
                self.hotness_count = reader.read_short()
            elif pointer_size == 8:
                self.declaring_class = reader.read_int()
                self.access_flags = reader.read_int()
                self.dex_code_item_offset = reader.read_int()
                self.dex_method_index = reader.read_int()
                self.method_index = reader.read_short()
                self.hotness_count = reader.read_short()
                self.imt_index = reader.read_short()
                self.padding = reader.read_short()

        elif art_version == "PIE_RELEASE":
            if pointer_size == 4:
                self.declaring_class = reader.read_int()
                self.access_flags = reader.read_int()
                self.dex_code_item_offset = reader.read_int()
                self.dex_method_index = reader.read_int()
                self.method_index = reader.read_short()
                self.hotness_count = reader.read_short()

        elif art_version == "10_RELEASE":
            if pointer_size == 4:
                self.declaring_class = reader.read_int()
                self.access_flags = reader.read_int()
                self.dex_code_item_offset = reader.read_int()
                self.dex_method_index = reader.read_int()
                self.method_index = reader.read_short()
                self.hotness_count = reader.read_short()

        elif art_version == "11_RELEASE":
            if pointer_size == 4:
                self.declaring_class = reader.read_int()
                self.access_flags = reader.read_int()
                self.dex_code_item_offset = reader.read_int()
                self.dex_method_index = reader.read_int()
                self.method_index = reader.read_short()
                self.hotness_count = reader.read_short()

        else:
            raise Exception("Unsupported ART method format: " + art_version)

    def get_declaring_class(self):
        return self.declaring_class

    def get_access_flags(self):
        return self.access_flags

    # ... and so on for the rest of the methods
