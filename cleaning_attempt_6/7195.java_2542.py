class OatHeaderOreoM2:
    def __init__(self):
        self.adler32_checksum = None
        self.instruction_set = None
        self.instruction_set_features_bitmap = None
        self.dex_file_count = None
        self.oat_dex_files_offset = None
        self.executable_offset = None
        self.interpreter_to_interpreter_bridge_offset = None
        self.interpreter_to_compiled_code_bridge_offset = None
        self.jni_dlsym_lookup_offset = None
        self.quick_generic_jni_trampoline_offset = None
        self.quick_imt_conflict_trampoline_offset = None
        self.quick_resolution_trampoline_offset = None
        self.quick_to_interpreter_bridge_offset = None
        self.image_patch_delta = None
        self.image_file_location_oat_checksum = None
        self.image_file_location_oat_data_begin = None
        self.key_value_store_size = None

    def parse(self, reader):
        count = 0
        while count < self.key_value_store_size:
            key = reader.read_next_ascii_string()
            value = reader.read_next_ascii_string()
            count += len(key) + 1
            count += len(value) + 1
            self.key_ = {key: value}
            self.ordered_key_list.append(key)

        reader.set_pointer_index(self.oat_dex_files_offset)
        for i in range(self.dex_file_count):
            oatdexfilelist.add(OatDexFileFactory.get_oatdexfile(reader, None))

    def get_dxelfilecount(self):
        return self.dex_file_count

    def get_key_value_store_size(self):
        return self.key_value_store_size

    def get_oat_dex_file_list(self):
        return oatdexfilelist

    def get_instruction_set(self):
        return OatInstructionSet.valueOf(self.instruction_set)

    def get_executable_offset(self):
        return self.executable_offset

    def get_interpreter_to_interpreter_bridge_offset(self):
        return self.interpreter_to_interpreter_bridge_offset

    def get_instruction_set_features_bitmap(self):
        return self.instruction_set_features_bitmap

    def get_jni_dlsym_lookup_offset(self):
        return self.jni_dlsym_lookup_offset

    def get_quick_generic_jni_trampoline_offset(self):
        return self.quick_generic_jni_trampoline_offset

    def get_quick_imt_conflict_trampoline_offset(self):
        return self.quick_imt_conflict_trampoline_offset

    def get_quick_resolution_trampoline_offset(self):
        return self.quick_resolution_trampoline_offset

    def get_quick_to_interpreter_bridge_offset(self):
        return self.quick_to_interpreter_bridge_offset

    def get_checksum(self):
        return self.adler32_checksum

    def to_data_type(self):
        structure = StructureDataType(OatHeaderOreoM2.__name__, 0)
        structure.add("magic_", "4", None)
        structure.add("version_", "4", None)
        structure.add("adler32_checksum_", "DWORD", None)
        structure.add(OatInstructionSet.DISPLAY_NAME, "DWORD", None)
        structure.add("instruction_set_features_bitmap_", "DWORD", None)
        structure.add("dex_file_count_", "DWORD", None)
        structure.add("oat_dex_files_offset_", "DWORD", None)
        structure.add("executable_offset_", "DWORD", None)
        structure.add("interpreter_to_interpreter_bridge_offset_", "DWORD", None)
        structure.add("interpreter_to_compiled_code_bridge_offset_", "DWORD", None)
        structure.add("jni_dlsym_lookup_offset_", "DWORD", None)
        structure.add("quick_generic_jni_trampoline_offset_", "DWORD", None)
        structure.add("quick_imt_conflict_trampoline_offset_", "DWORD", None)
        structure.add("quick_resolution_trampoline_offset_", "DWORD", None)
        structure.add("quick_to_interpreter_bridge_offset_", "DWORD", None)
        structure.add("image_patch_delta_", "DWORD", None)
        structure.add("image_file_location_oat_checksum_", "DWORD", None)
        structure.add("image_file_location_oat_data_begin_", "DWORD", None)
        structure.add("key_value_store_size_", "DWORD", None)

        for i in range(len(self.ordered_key_list)):
            key = self.ordered_key_list[i]
            value = self.key_[key]
            structure.add(key + "_value_" + str(i), len(value) + 1, None)
        return structure
