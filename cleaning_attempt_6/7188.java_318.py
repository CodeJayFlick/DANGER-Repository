class OatHeader10:
    def __init__(self):
        self.oat_checksum = None
        self.instruction_set = None
        self(instruction_set_features_bitmap) = None
        self.dex_file_count = None
        self.oat_dex_files_offset = None
        self.executable_offset = None
        self.jni_dlsym_lookup_offset = None
        self.quick_generic_jni_trampoline_offset = None
        self.quick_imt_conflict_trampoline_offset = None
        self.quick_resolution_trampoline_offset = None
        self.quick_to_interpreter_bridge_offset = None
        self.key_value_store_size = None

    def parse(self, reader):
        count = 0
        while count < self.key_value_store_size:
            key = reader.read_next_ascii_string()
            value = reader.read_next_ascii_string()
            count += len(key) + 1
            count += len(value) + 1
            # orderedKeyList.add(key)
            # key_value_store_.put(key, value)

    def get_dex_file_count(self):
        return self.dex_file_count

    def get_key_value_store_size(self):
        return self.key_value_store_size

    def get_oat_dex_file_list(self):
        return []

    def get_instruction_set(self):
        # OatInstructionSet.valueOf(instruction_set)
        pass

    def get_executable_offset(self):
        return self.executable_offset

    def get_checksum(self):
        return self.oat_checksum
