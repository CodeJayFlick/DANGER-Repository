Here is the translation of the Java code into Python:

```Python
class ExportDataDirectory:
    NAME = "IMAGE_DIRECTORY_ENTRY_EXPORT"
    IMAGE_SIZEOF_EXPORT_DIRECTORY = 40

    def __init__(self):
        pass

    @staticmethod
    def create_export_data_directory(nt_header, reader) -> 'ExportDataDirectory':
        export_data_directory = ExportDataDirectory()
        export_data_directory.init_export_data_directory(nt_header, reader)
        return export_data_directory

    def init_export_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

        if not hasattr(self, 'exports'):
            self.exports = []

    def get_exports(self) -> list:
        return self.exports

    def get_address_of_functions(self) -> int:
        return self.address_of_functions

    def get_address_of_names(self) -> int:
        return self.address_of_names

    def get_address_of_name_ordinals(self) -> int:
        return self.address_of_name_ordinals

    def get_number_of_functions(self) -> int:
        return self.number_of_functions

    def get_number_of_names(self) -> int:
        return self.number_of_names

    def get_name(self) -> int:
        return self.name

    def get_base(self) -> int:
        return self.base

    def get_characteristics(self) -> int:
        return self.characteristics

    def get_time_date_stamp(self) -> int:
        return self.time_date_stampt

    def get_major_version(self) -> short:
        return self.major_version

    def get_minor_version(self) -> short:
        return self.minor_version

    def get_export_name(self) -> str:
        return self.export_name

    @staticmethod
    def markup(program, is_binary, monitor, log, nt_header):
        if not program.get_memory().contains(virtual_address):
            return

        create_directory_bookmark(program, virtual_address)

        address_space = program.get_address_factory().get_default_address_space()
        reference_manager = program.get_reference_manager()

        # Apply the export directory data structure
        pe_utils.create_data(program, virtual_address, to_data_type(), log)

        if name > 0:
            ptr_to_name = va(name, is_binary)
            create_terminated_string(program, str_addr, False, log)
            set_plate_comment(program, str_addr, "Export Library Name")

        func_addr = va(address_of_functions, is_binary)
        name_addr = va(address_of_names, is_binary)
        ordinal_addr = va(address_of_name_ordinals, is_binary)

        for i in range(number_of_functions):
            if monitor.is_cancelled():
                break

            address = space.get_address(func_addr)
            set_plate_comment(program, address, "Export Function Pointers")

            pe_utils.create_data(program, address, new_dword_data_type(), log)
            data = program.get_listing().get_data_at(address)

            scalar = (scalar) data.get_value()
            str_addr = space.get_address(va(scalar.get_unsigned_value(), is_binary))
            data.add_operand_reference(0, str_addr, ref_type.data, source_type.imported)
            reference_manager.set_primary(ref, False)

        for i in range(number_of_names):
            if monitor.is_cancelled():
                break

            address = space.get_address(name_addr)
            set_plate_comment(program, address, "Export Ordinal Values")

            pe_utils.create_data(program, address, new_word_data_type(), log)
            ordinal_addr += 2
        for i in range(number_of_names):
            if monitor.is_cancelled():
                break

            address = space.get_address(name_addr)
            set_plate_comment(program, address, "Export Name Pointers")

            pe_utils.create_data(program, address, new_dword_data_type(), log)
            data = program.get_listing().get_data_at(address)

            scalar = (scalar) data.get_value()
            str_addr = space.get_address(va(scalar.get_unsigned_value(), is_binary))
            data.add_operand_reference(0, str_addr, ref_type.data, source_type.imported)
            reference_manager.set_primary(ref, False)

    def get_directory_name(self):
        return self.name

    @staticmethod
    def parse(reader) -> bool:
        old_index = reader.get_pointer_index()
        try:
            ptr = get_pointer()

            if ptr < 0:
                return false

            reader.set_pointer_index(ptr)
            characteristics = reader.read_next_int()
            time_date_stampt = reader.read_next_int()
            major_version = reader.read_next_short()
            minor_version = reader.read_next_short()
            name = reader.read_next_int()
            base = reader.read_next_int()
            number_of_functions = reader.read_next_int()
            number_of_names = reader.read_next_int()
            address_of_functions = reader.read_next_int()
            address_of_names = reader.read_next_int()
            address_of_name_ordinals = reader.read_next_int()

            exports_start_rva = get_virtual_address()
            exports_end_rva = exports_start_rva + size

            export_name = "" if ptr < 0 else reader.read_ascii_string(ptr)

            list_export_info = []

            for i in range(number_of_functions):
                entry_point_rva = reader.read_int(pointer_to_functions)
                pointer_to_functions += 4
                # Skip over gaps in exported function ordinals (the entrypoint is 0 for these functions).
                if entry_point_rva == 0:
                    continue

                addr = Conv.int_to_long(entry_point_rva) + nt_header.get_optional_header().get_image_base()

                if not nt_header.get_optional_header().is_64bit():
                    addr &= 0xffffffffL

                str_addr = ""

                # See if this function has an associated name exported for it.
                for j in range(number_of_names):
                    jth_ordinal_val = reader.read_short(pointer_to_ordinals + (j * 2))
                    if jth_ordinal_val == i:
                        jth_name_rva = reader.read_int(pointer_to_names + (j * 4))
                        jth_name_ptr = nt_header.rva_to_pointer(jth_name_rva)
                        if jth_name_ptr < 0:
                            Msg.error(self, "Invalid RVA " + Integer.toHexString(jth_name_rva))
                            return False
                        # Locate corresponding name.
                        str_addr = reader.read_ascii_string(jth_name_ptr)
                        break

                cmt = f"0x{Long.toHexString(addr)} {i+base} {str_addr}"

                if entry_point_rva >= exports_start_rva and entry_point_rva < exports_end_rva:
                    entry_point_ptr = nt_header.rva_to_pointer(entry_point_rva)
                    if entry_point_ptr < 0:
                        Msg.error(self, "Invalid RVA " + Integer.toHexString(entry_point_rva))
                        return False
                    forwarder = reader.read_ascii_string(entry_point_ptr)

                    cmt += f" ({forwarder})"
                    forwarded = True

                list_export_info.append(ExportInfo(addr, i+base, str_addr, cmt, forwarded))

            exports = [ExportInfo(*x) for x in zip(list_export_info)]

        finally:
            reader.set_pointer_index(old_index)
        return True
```

Note that this is a direct translation of the Java code into Python. The resulting Python code may not be idiomatic or optimized for performance.