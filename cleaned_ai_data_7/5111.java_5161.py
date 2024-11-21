class DelayImportDescriptor:
    NAME = "ImgDelayDescr"

    def __init__(self):
        self.gr_attrs = 0
        self.sz_name = 0
        self.phmod = 0
        self.p_iat = 0
        self.p_int = 0
        self.p_bound_iat = 0
        self.p_unload_iat = 0
        self.dw_timestamp = 0

    @staticmethod
    def create_delay_import_descriptor(nt_header, reader, index):
        delay_import_descriptor = DelayImportDescriptor()
        delay_import_descriptor.init_delay_import_descriptor(nt_header, reader, index)
        return delay_import_descriptor

    def init_delay_import_descriptor(self, nt_header, reader, index):
        if not nt_header.check_pointer(index):
            print("Invalid file index for " + hex(index))
            return
        self.read_fields(reader, index)

    def read_fields(self, reader, index):
        self.gr_attrs = reader.readInt32(index)
        index += 4
        self.sz_name = reader.readInt32(index) & Conv.INT_MASK
        index += 4
        self.phmod = reader.readInt32(index) & Conv.INT_MASK
        index += 4
        self.p_iat = reader.readInt32(index) & Conv.INT_MASK
        index += 4
        self.p_int = reader.readInt32(index) & Conv.INT_MASK
        index += 4
        self.p_bound_iat = reader.readInt32(index) & Conv.INT_MASK
        index += 4
        self.p_unload_iat = reader.readInt32(index) & Conv.INT_MASK
        index += 4
        self.dw_timestamp = reader.readInt32(index)

    def is_using_rva(self):
        return (self.gr_attrs & 1) == 1

    @property
    def attributes(self):
        return self.gr_attrs

    @property
    def pointer_to_dll_name(self):
        return self.sz_name

    @property
    def address_of_module_handle(self):
        return self.phmod

    @property
    def address_of_iat(self):
        return self.p_iat

    @property
    def address_of_int(self):
        return self.p_int

    @property
    def address_of_bound_iat(self):
        return self.p_bound_iat

    @property
    def address_of_original_iat(self):
        return self.p_unload_iat

    @property
    def time_stamp(self):
        return self.dw_timestamp

    @property
    def dll_name(self):
        return ""

    @property
    def import_by_name_map(self):
        return {}

    @property
    def delay_import_info_list(self):
        return []

    @property
    def thunks_iat(self):
        return []

    @property
    def thunks_int(self):
        return []

    @property
    def thunks_bound_iat(self):
        return []

    @property
    def thunks_unload_iat(self):
        return []
