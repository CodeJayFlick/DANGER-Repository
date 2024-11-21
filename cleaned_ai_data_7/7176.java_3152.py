class OatDexFileKitKat:
    def __init__(self):
        self.dex_file_location_size = None
        self.dex_file_location = None
        self.dex_file_location_checksum = None
        self.dex_file_pointer = None
        self.oat_class_offsets_pointer = []

    def read(self, reader):
        try:
            self.dex_file_location_size = reader.read_int()
            self.dex_file_location = reader.read_ascii_string(self.dex_file_location_size)
            self.dex_file_location_checksum = reader.read_int()
            self.dex_file_pointer = reader.read_int()

            provider = reader.get_byte_provider()
            tmp_provider = ByteProviderWrapper(provider, self.dex_file_pointer,
                                                 len(provider) - self.dex_file_pointer)
            tmp_reader = BinaryReader(tmp_provider, not reader.is_little_endian())
            self.dex_header = DexHeaderFactory().get_dex_header(tmp_reader)

            size = self.dex_header.get_class_defs().size()
            if size == 0:
                self.oat_class_offsets_pointer = []
            else:
                self.oat_class_offsets_pointer = reader.read_int_array(size)
        except Exception as e:
            print(f"Error: {e}")

    def get_dex_file_location(self):
        return self.dex_file_location

    def get_dex_file_checksum(self):
        return self.dex_file_location_checksum

    def get_dex_file_offset(self):
        return self.dex_file_pointer

    def get_dex_header(self):
        return self.dex_header

    def is_dex_header_external(self):
        return False

    def markup(self, oat_header, program, monitor, log):
        try:
            symbol = OatUtilities().get_oat_data_symbol(program)
            address = symbol.get_address()

            listing = program.get_listing()
            reference_manager = program.get_reference_manager()
            memory = program.get_memory()
            data = listing.get_defined_data_at(address)

            if data is None or not isinstance(data, Data) or \
               not data.get_data_type().get_name().startswith("OatHeader"):
                return

            oat_dex_file_header_data_list = self.get_oat_dex_file_header_data(data, monitor)
            for i in range(len(oat_dex_file_header_data_list)):
                monitor.check_canceled()
                log.append_msg(f"Processing {i} of {len(oat_dex_file_header_data_list)}")

        except Exception as e:
            print(f"Error: {e}")

    def get_oat_dex_file_header_data(self, data, monitor):
        list = []
        for i in range(data.get_num_components()):
            component_i = data.get_component(i)
            if isinstance(component_i, Data) and \
               component_i.get_field_name().startswith(OatDexFile.PREFIX):
                list.append(component_i)

        return list

    def markup_dex_class_offset(self, oat_header, program, symbol, dex_class_offsets_data,
                                 monitor, log):
        try:
            reference_manager = program.get_reference_manager()
            for j in range(dex_class_offsets_data.get_num_components()):
                component_j = dex_class_offsets_data.get_component(j)
                if isinstance(component_j, Data) and \
                   component_j.get_field_name().startswith("oat_class_ offsets_pointer"):
                    scalar = component_j.get_scalar(0)
                    to_addr = symbol.get_address().add(scalar.get_unsigned_value())
                    reference_manager.add_memory_reference(
                        component_j.get_min_address(), to_addr,
                        RefType.DATA, SourceType.ANALYSIS, 0)

        except Exception as e:
            print(f"Error: {e}")

    def markup_method(self, oat_header, oat_class_header, dex_header, class_def_item,
                      program, symbol_table, symbol, namespace, log):
        try:
            if class_def_item.get_class_data_offset() == 0:
                return

            all_methods = OatUtilities().get_all_methods(class_def_item)
            for j in range(len(all_methods)):
                monitor.check_canceled()
                method_offset = oat_class_header.get_method_offsets()[j]
                to_addr = symbol.get_address().add(method_offset.get_code_offset())
                encoded_method = all_methods[j]

        except Exception as e:
            print(f"Error: {e}")

    def markup_class_header_data(self, program, symbol, address, oat_header,
                                  oat_class_header, log):
        try:
            listing = program.get_listing()
            reference_manager = program.get_reference_manager()

            data = listing.create_data(address, oat_class_header.to_data_type())
            for j in range(data.get_num_components()):
                monitor.check_canceled()
                component_j = data.get_component(j)
                if isinstance(component_j, Data) and \
                   component_j.get_field_name().startswith("method_offsets_"):
                    method_offset_data = component_j.get_component(0)
                    scalar = method_offset_data.get_scalar(0)

        except Exception as e:
            print(f"Error: {e}")

    def to_data_type(self):
        try:
            structure = StructureDataType(OatDexFileKitKat.__name__ + "_" +
                                            len(self.oat_class_offsets_pointer), 0)
            structure.add(DWORD, "dex_file_location_size", None)
            structure.add(STRING, self.dex_file_location, "dex_file_location", None)
            structure.add(DWORD, "dex_file_location_checksum", None)

            dex_class_offsets_structure = StructureDataType("dexClassOffsets_" +
                                                              len(self.oat_class_offsets_pointer), 0)
            for i in range(len(self.oat_class_offsets_pointer)):
                dex_class_offsets_structure.add(DWORD,
                                                  f"oat_class_offsets_pointer_{i}", None)

            structure.add(dex_class_offsets_structure, "dexClassOffsets", None)

        except Exception as e:
            print(f"Error: {e}")

        return structure
