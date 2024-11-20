class OatHeaderLollipop:
    def __init__(self):
        self.adler32_checksum = None
        self.instruction_set = None
        self.instruction_set_features = None
        self.dex_file_count = None
        self.executable_offset = None
        self.interpreter_to_interpreter_bridge_offset = None
        self.interpreter_to_compiled_code_bridge_offset = None
        self.jni_dlsym_lookup_offset = None
        self.portable_imt_conflict_trampoline_offset = None
        self.portable_resolution_trampoline_offset = None
        self.portable_to_interpreter_bridge_offset = None
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
            # todo: implement the logic to store and order keys in a list

    def get_dex_file_count(self):
        return self.dex_file_count

    def get_key_value_store_size(self):
        return self.key_value_store_size

    def get_oat_dex_file_list(self):
        return []  # todo: implement this method

    def get_instruction_set(self):
        pass  # todo: implement this method

    def get_executable_offset(self):
        return self.executable_offset

    def get_checksum(self):
        return self.adler32_checksum

    @staticmethod
    def to_data_type():
        structure = {}
        for key, value in locals().items():
            if isinstance(value, int) or isinstance(value, str):
                structure[key] = value
        return structure


class OatDexFile:
    pass  # todo: implement this class

def main():
    reader = BinaryReader()  # todo: implement the binary reader
    oat_header_lollipop = OatHeaderLollipop()
    oat_header_lollipop.parse(reader)
    print(oat_header_lollipop.get_dex_file_count())
    print(oat_header_lollipop.get_key_value_store_size())

if __name__ == "__main__":
    main()

