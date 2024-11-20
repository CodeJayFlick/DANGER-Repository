class ImageRuntimeFunctionEntries:
    UNWIND_INFO_SIZE = 0x0C

    def __init__(self):
        self.function_entries = []

    @staticmethod
    def create_image_runtime_function_entries(reader, index, nt_header) -> 'ImageRuntimeFunctionEntries':
        image_runtime_function_entries_section = ImageRuntimeFunctionEntries()
        image_runtime_function_entries_section.init_image_runtime_function_entries(reader, index, nt_header)
        return image_runtime_function_entries_section

    def init_image_runtime_function_entries(self, reader, index, nt_header):
        entry_count = 0
        for section in nt_header.file_header.section_headers:
            if section.name == ".pdata":
                entry_count = section.size_of_raw_data() // self.UNWIND_INFO_SIZE
                break

        if entry_count == 0:
            return

        orig_index = reader.pointer_index()
        reader.set_pointer_index(index)

        for i in range(entry_count):
            entry = _IMAGE_RUNTIME_FUNCTION_ENTRY()
            entry.begin_address = reader.read_next_unsigned_int()
            entry.end_address = reader.read_next_unsigned_int()
            entry.unwind_info_address_or_data = reader.read_next_unsigned_int()

            if (entry.begin_address == 0 and
                    entry.end_address == 0 and
                    entry.unwind_info_address_or_data == 0):
                break

            entry.unwind_info = PEx64UnwindInfo().read_unwind_info(reader, entry.unwind_info_address_or_data, nt_header)
            self.function_entries.append(entry)

        reader.set_pointer_index(orig_index)

    def get_runtime_function_entries(self) -> list:
        return self.function_entries


class _IMAGE_RUNTIME_FUNCTION_ENTRY:
    def __init__(self):
        self.begin_address = 0
        self.end_address = 0
        self.unwind_info_address_or_data = 0
        self.unwind_info = None

    def create_data(self, program: Program) -> None:
        if self.unwind_info_address_or_data > 0:
            try:
                dt = self.unwind_info.to_data_type()
                start = program.image_base().add(self.unwind_info_address_or_data)
                DataUtilities.create_data(program, start, dt, dt.length(), True,
                                           DataUtilities.ClearDataMode.CHECK_FOR_SPACE)
            except (CodeUnitInsertionException, DuplicateNameException, IOException):
                pass


class PEx64UnwindInfo:
    @staticmethod
    def read_unwind_info(reader: 'Reader', address_or_data: int, nt_header) -> '_Pex64UnwindInfo':
        # TODO: implement this method
        return None

