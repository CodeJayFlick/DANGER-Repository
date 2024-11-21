Here is the translation of the Java code into equivalent Python:

```Python
class OatDexFileUtilities:
    def markup_lookup_table_data(self, caller: str, address: int, dex_header: dict,
                                  oat_header: dict, program: object, monitor: object, log: object):
        if not dex_header:
            log.append_msg(f"{caller}-markupLookupTableData()-no-dex-header-skipping...")
            return

        monitor.set_message("OAT-Processing-Lookup-Table-Data...")
        monitor.set_maximum(dex_header['class_defs_ids_size'])
        monitor.set_progress(0)

        oat_data_symbol = OatUtilities.get_oat_data_symbol(program)
        dword_type = DWordDataType()
        try:
            for i in range(dex_header['class_defs_ids_size']):
                program.listing.create_data(address, dword_type)
                value = program.memory.get_int(address)
                destination_address = oat_data_symbol.address + value

                program.reference_manager.add_memory_reference(
                    address, destination_address, RefType.DATA, SourceType.ANALYSIS, 0
                )
                address += dword_type.length()

                class_def_item = dex_header['class_defs'][i]
                class_name = DexUtil.convert_type_index_to_string(dex_header, class_def_item['class_index'])
                namespace = DexUtil.create_namespace_from_mangled_class_name(program, class_name)

                oat_class_header_provider = MemoryByteProvider(
                    program.memory, destination_address
                )
                binary_reader = BinaryReader(oat_class_header_provider, not program.language.is_big_endian())

                oat_class_header = OatClass(binary_reader, class_def_item['class_data_item'], oat_header['version'])

                self.markup_method(oat_header, oat_class_header, dex_header, class_def_item, program,
                                   oat_data_symbol, namespace, log, monitor)

                self.markup_class_header_data(program, oat_data_symbol, destination_address, oat_header, oat_class_header, log, monitor)
                monitor.set_progress(i)
        except Exception as e:
            log.append_exception(e)

    def markup_method(self, oat_header: dict, oat_class_header: object, dex_header: dict,
                      class_def_item: dict, program: object, oat_data_symbol: object, namespace: object,
                      log: object, monitor: object):
        if not class_def_item['class_data_offset']:
            return

        symbol_table = program.symbol_table
        all_methods = OatUtilities.get_all_methods(class_def_item['class_data_item'])

        for j in range(len(all_methods)):
            monitor.check_canceled()

            method_offset = oat_class_header.method_offsets[j]
            if not method_offset.code_offset:
                continue  # TODO what does 0 mean?

            to_address = oat_data_symbol.address + method_offset.code_offset
            to_address = OatUtilities.adjust_for_thumb_as_needed(oat_header, program, to_address, log)

            encoded_method = all_methods[j]
            method_id_item = dex_header['methods'][encoded_method.method_index]

            method_name = DexUtil.convert_to_string(dex_header, method_id_item.name_index)
            symbol_table.create_label(to_address, method_name, namespace, SourceType.ANALYSIS)

    def markup_class_header_data(self, program: object, oat_data_symbol: object,
                                  address: int, oat_header: dict, oat_class_header: object, log: object,
                                  monitor: object):
        try:
            symbol_table = program.symbol_table
            reference_manager = program.reference_manager
            listing = program.listing

            data = listing.create_data(address, oat_class_header.to_data_type())
            for j in range(data.num_components()):
                monitor.check_canceled()
                component = data.get_component(j)
                if component.field_name.startswith('method_offsets_'):
                    method_offset_data = component.get_component(0)
                    scalar = method_offset_data.scalar[0]
                    if not scalar.unsigned_value:
                        continue  # TODO what does 0 mean?

                    to_address = oat_data_symbol.address + scalar.unsigned_value
                    to_address = OatUtilities.adjust_for_thumb_as_needed(oat_header, program, to_address, log)
                    reference_manager.add_memory_reference(
                        component.min_address(), to_address, RefType.READ, SourceType.ANALYSIS, 0
                    )
                    symbol_table.add_external_entry_point(to_address)

                    # Lays down quick header in listing right before the method
                    quick_header_address = to_address - OatQuickMethodHeaderFactory.get_oat_quick_method_header_size(oat_header['version'])
                    if not listing.is_undefined(quick_header_address, quick_header_address):
                        oqmh_provider = MemoryByteProvider(program.memory, quick_header_address)
                        binary_reader = BinaryReader(oqmh_provider, not program.language.is_big_endian())
                        oat_quick_method_header = OatQuickMethodHeaderFactory.get_oat_quick_method_header(binary_reader, oat_header['version'])
                        data_type = oat_quick_method_header.to_data_type()
                        listing.create_data(quick_header_address, data_type)
        except Exception as e:
            log.append_exception(e)

    def get_next_power_of_two(self, value: int):
        highest_bit = value.bit_length() - 1
        if not (value & ((1 << highest_bit) - 1)):
            return value
        return (highest_bit + 1) << 1

    def markup_oat_class_offsets_pointer(self, caller: str, address: int, dex_header: dict,
                                          oat_header: dict, program: object, monitor: object, log: object):
        if not dex_header:
            log.append_msg(f"{caller}-markupOatClassOffsetsPointer()-no-dex-header-skipping...")
            return

        monitor.set_message("Processing Oat Class Offset Pointers...")

        size = dex_header['class_defs_ids_size']
        size *= 2
        size = self.get_next_power_of_two(size)

        dword_type = DWordDataType()
        array_data_type = ArrayDataType(dword_type, size, dword_type.length())
        try:
            program.listing.create_data(address, array_data_type)
        except Exception as e:
            log.append_exception(e)


# Example usage
oat_dex_file_utilities = OatDexFileUtilities()

caller = "Example"
address = 0x10000000
dex_header = {"class_defs_ids_size": 10}
oat_header = {"version": 1.2}
program = object()
monitor = object()
log = object()

oat_dex_file_utilities.markup_lookup_table_data(caller, address, dex_header, oat_header, program, monitor, log)
```

Please note that Python does not support direct translation of Java code into equivalent Python. The above Python code is a manual translation and may have some differences in terms of syntax or functionality compared to the original Java code.