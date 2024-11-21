Here is the translation of the given Java code into equivalent Python:

```Python
class OatDexFilePie:
    def __init__(self, reader, vdex_header):
        self._offset = reader.get_pointer_index()
        self.dex_file_location_ = reader.read_next_int()
        self.canonical_dex_file_location_ = reader.read_ascii_string(self.dex_file_location_)
        self.dex_file_location_checksum_ = reader.read_next_int()
        self.dex_file_pointer_ = reader.read_next_int()
        self.lookup_table_data_ = reader.read_next_int()
        self.method_bss_mapping_ = reader.read_next_int()
        self.type_bss_mapping_ = reader.read_next_int()
        self.string_bss_mapping_ = reader.read_next_int()
        self.oat_class_offsets_pointer_ = reader.read_next_int()
        self.lookup_table_ = reader.read_next_int()

        if vdex_header is not None:
            for i in range(len(vdex_header.dex_checksums)):
                if vdex_header.dex_checksums[i] == self.get_dex_file_checksum():
                    if len(vdex_header.dex_header_list) > i:
                        self.dex_header = vdex_header.dex_header_list[i]
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

    def get_lookup_table(self):
        return self.lookup_table_

    def get_lookup_table_data(self):
        return self.lookup_table_data_

    def get_method_bss_mapping(self):
        return self.method_bss_mapping_

    def get_type_bss_mapping(self):
        return self.type_bss_mapping_

    def get_string_bss_mapping(self):
        return self.string_bss_mapping_

    def get_oat_class_offsets_pointer(self):
        return self.oat_class_offsets_pointer_

    #def get_dex_layout_sections(self):  # according to spec this field should exist, but it does not

    def markup(self, oat_header, program, monitor, log):
        symbol = OatUtilities.get_oat_data_symbol(program)
        address = symbol.get_address()

        data_address = address.add(self._offset)
        data = program.get_listing().create_data(data_address, self.to_data_type())

        for i in range(data.num_components()):
            monitor.check_canceled()
            component_i = data.component(i)

            if (component_i.field_name.startswith("lookup_table_") or
                component_i.field_name.startswith("oat_class_offsets_pointer_") or
                component_i.field_name.startswith("method_bss_mapping_") or
                component_i.field_name.startswith("type_bss_mapping_") or
                component_i.field_name.startswith("string_bss_mapping_")):
                scalar = component_i.scalar(0)
                if scalar.get_unsigned_value() == 0:
                    continue

                destination_address = address.add(scalar.get_unsigned_value())
                program.reference_manager().add_memory_reference(component_i.min_address(), 
                                                                  destination_address, RefType.DATA, SourceType.ANALYSIS, 0)

                symbol_table = program.symbol_table()
                label = symbol_table.create_label(destination_address, component_i.field_name, SourceType.ANALYSIS)
            elif (component_i.field_name.startswith("lookup_table_data_")):
                OatDexFileUtilities.markup_lookup_table_data(self.__class__, destination_address, 
                                                              self.dex_header, oat_header, program, monitor, log)

    def to_data_type(self):
        class_name = StructConverterUtil.parse_name(OatDexFilePie)
        structure = StructureDataType(class_name + "_" + str(self.dex_file_location_) + "_", 0)

        structure.add(DWORD, "dex_file_location_", None)
        structure.add(STRING, self.canonical_dex_file_location_, "canonical_dex_file_location_", None)
        structure.add(DWORD, "dex_file_location_checksum_", None)
        structure.add(DWORD, "dex_file_pointer_", None)
        structure.add(DWORD, "lookup_table_data_", None)
        structure.add(DWORD, "method_bss_mapping_", None)
        structure.add(DWORD, "type_bss_mapping_", None)
        structure.add(DWORD, "string_bss_mapping_", None)
        structure.add(DWORD, "oat_class_offsets_pointer_", None)
        structure.add(DWORD, "lookup_table_", None)

        #structure.add( DWORD,  "dex_layout_sections_" , None )  # according to spec this field should exist, but it does not

        structure.set_category_path(CategoryPath("/oat"))
        return structure
```

Note: This Python code is equivalent to the given Java code. However, please note that some fields and methods are commented out in the original Java code (like `get_dex_layout_sections`), which means they should exist according to specifications but do not actually exist.