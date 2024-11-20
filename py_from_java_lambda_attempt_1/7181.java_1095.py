Here is the translation of the given Java code into equivalent Python:

```Python
class OatDexFileOreoM2:
    def __init__(self, reader, vdex_header):
        self._offset = reader.get_pointer_index()
        self.dex_file_location_ = reader.read_next_int()
        self.canonical_dex_file_location_ = reader.read_next_ascii_string(self.dex_file_location_)
        self.dex_file_location_checksum_ = reader.read_next_int()
        self.dex_file_pointer_ = reader.read_next_int()
        self.lookup_table_data_ = reader.read_next_int()
        self.method_bss_mapping_ = reader.read_next_int()
        self.oat_class_offsets_pointer_ = reader.read_next_int()
        self.dex_cache_arrays_ = reader.read_next_int()

        if vdex_header is not None:
            for i in range(len(vdex_header.get_dex_checksums())):
                if vdex_header.get_dex_checksums()[i] == self.get_dex_file_checksum():
                    self.dex_header = vdex_header.get_dex_header_list().get(i)
                    break

    def get_dex_file_checksum(self):
        return self.dex_file_location_checksum_

    def get_dex_header(self):
        return self.dex_header

    def get_dex_file_offset(self):
        return self.dex_file_pointer_

    def get_dex_file_location(self):
        return self.canonical_dex_file_location_

    def is_dex_header_external(self):
        return True

    def get_lookup_table_data(self):
        return self.lookup_table_data_

    def get_method_bss_mapping(self):
        return self.method_bss_mapping_

    def get_oat_class_offsets_pointer(self):
        return self.oat_class_offsets_pointer_

    def get_dex_cache_arrays(self):
        return self.dex_cache_arrays_

    def markup(self, oat_header, program, monitor, log):
        symbol = OatUtilities.get_oat_data_symbol(program)
        address = symbol.get_address()

        data_address = address.add(self._offset)
        data = program.get_listing().create_data(data_address, self.to_data_type())

        for i in range(data.get_num_components()):
            if data.get_component(i).get_field_name().startswith("lookup_table_data_") or \
               data.get_component(i).get_field_name().startswith("oat_class_offsets_pointer_") or \
               data.get_component(i).get_field_name().startswith("method_bss_mapping_"):
                scalar = data.get_scalar(0)
                destination_address = address.add(scalar.get_unsigned_value())
                program.get_reference_manager()\
                      .add_memory_reference(data.get_min_address(), destination_address, RefType.DATA, SourceType.ANALYSIS, 0)

    def to_data_type(self):
        structure = StructureDataType("OatDexFile_" + str(self.dex_file_location_) + "_")
        structure.add(DWORD, "dex_file_location_", None)
        structure.add(STRING, self.canonical_dex_file_location_, "canonical_dex_file_location_", None)
        structure.add(DWORD, "dex_file_location_checksum_", None)
        structure.add(DWORD, "dex_file_pointer_", None)
        structure.add(DWORD, "lookup_table_data_", None)
        structure.add(DWORD, "method_bss_mapping_", None)
        structure.add(DWORD, "oat_class_offsets_pointer_", None)
        structure.add(DWORD, "dex_cache_arrays_", None)

        structure.set_category_path(CategoryPath("/oat"))
        return structure
```

Please note that Python does not have direct equivalents for Java classes like `BinaryReader`, `StructConverterUtil` and others. These need to be replaced with equivalent functionality in the given code.