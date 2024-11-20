Here is the translation of the Java code into Python:

```Python
class RttiUtil:
    TYPE_INFO_NAMESPACE = "type_info"
    MIN_MATCHING_VFTABLE_PTRS = 5
    CONST_PREFIX = "const "

    TYPE_INFO_LABEL = "class_type_info_RTTI_Type_Descriptor"
    TYPE_INFO_STRING = ".?AVtype_info@@"

    CLASS_PREFIX_CHARS = ".?A"

    vftable_map = {}

    def __init__(self):
        pass

    @staticmethod
    def create_symbol_from_demangled_type(program, rtti_address, type_descriptor_model, rtti_suffix):
        if not isinstance(rtti_suffix, str):
            return False  # Not a string

        rtti_suffix = SymbolUtilities.replace_invalid_chars(rtti_suffix, True)

        class_namespace = type_descriptor_model.get_descriptor_as_namespace()

        ref_type = type_descriptor_model.get_ref_type()
        make_class = "class".casefold() == ref_type.casefold() or "struct".casefold() == ref_type.casefold()
        symbol_table = program.get_symbol_table()
        if make_class and class_namespace is not None and not isinstance(class_namespace, GhidraClass):
            try:
                class_namespace = NamespaceUtils.convert_namespace_to_class(class_namespace)
            except InvalidInputException as e:
                Msg.error(RttiUtil.__class__, "Unable to convert namespace to class for namespace {}.".format(class_namespace), e)

        matching_symbol = symbol_table.get_symbol(rtti_suffix, rtti_address, class_namespace)
        if matching_symbol is not None:
            return False

        # Don't create it if a similar symbol already exists at the address of the data.
        symbols = symbol_table.get_symbols_as_iterator(rtti_address)
        for symbol in symbols:
            name = symbol.name
            if rtti_suffix.casefold() in name.casefold():
                return False  # Similar symbol already exists.

            source_type = symbol.source
            if source_type == SourceType.IMPORTED:
                return False

        try:
            symbol_table.create_label(rtti_address, rtti_suffix, class_namespace, SourceType.IMPORTED)
            return True
        except InvalidInputException as e:
            Msg.error(RttiUtil.__class__, "Unable to create label for {} at {}".format(rtti_suffix, rtti_address), e)

    @staticmethod
    def get_vf_table_count(program, vf_table_base_address):
        memory = program.get_memory()
        reference_manager = program.get_reference_manager()
        function_manager = program.get_function_manager()

        text_block = memory.get_block(".text")
        nep_block = memory.get_block(".nep")

        initialized_addresses = memory.get_loaded_and_initialized_address_set()
        pseudo_disassembler = PseudoDisassembler(program)

        table_size = 0
        current_vf_pointer_address = vf_table_base_address

        while True:
            referenced_address = get_absolute_address(program, current_vf_pointer_address)
            if referenced_address is None:
                break  # Cannot get a virtual function address.

            if referenced_address.get_offset() == 0:
                break  # Encountered 0 entry.

            if not initialized_addresses.contains(referenced_address):
                break  # Not pointing to initialized memory.

            if text_block or nep_block:
                refed_block = memory.get_block(referenced_address)
                in_text_block = (text_block and text_block == refed_block) or \
                               ((nep_block and nep_block == refed_block))
                if not in_text_block:
                    break  # Not pointing to good section.

            function = function_manager.get_function_at(referenced_address)

            if function is None and pseudo_disassembler.is_valid_subroutine(referenced_address, True, False):
                break  # Not pointing to possible function.

            table_size += 1

            current_vf_pointer_address -= program.get_default_pointer_size()

        return table_size

    @staticmethod
    def get_descriptor_type_namespace(rtti0_model):
        descriptor_type_namespace = rtti0_model.get_descriptor_type_namespace()
        if descriptor_type_namespace is None:
            return ""

        return descriptor_type_namespace

    class CommonRTTIMatchCounter(TerminatingConsumer[Address]):
        def __init__(self, program):
            self.program = program
            self.default_pointer_size = program.get_default_pointer_size()

        @property
        def info_vftable_address(self):
            return self.common_vftable_address

        def termination_requested(self) -> bool:
            return self.termination_request

        def accept(self, address: Address):
            mangled_class_name_address = address

            pointer_to_type_info_vftable = mangled_class_name_address - 2 * self.default_pointer_size
            possible_vftable_address = MSDataTypeUtils.get_absolute_address(self.program, pointer_to_type_info_vftable)
            if possible_vftable_address is None:
                return  # valid address not found

            if possible_vftable_address.get_offset() == 0:
                return  # don't want zero_address to count

            self.common_vftable_address = possible_vftable_address
            self.matching_addr_count += 1

            if self.matching_addr_count > RttiUtil.MIN_MATCHING_VFTABLE_PTRS:
                self.termination_request = True
                return

        def __init__(self, program):
            super().__init__()
            self.program = program
            self.default_pointer_size = program.get_default_pointer_size()
            self.common_vftable_address = None
            self.matching_addr_count = 0
            self.termination_request = False

    @staticmethod
    def find_type_info_vftable_address(program, monitor):
        if vftable_map.get(program) is not None:
            return vftable_map[program]

        info_vftable_address = RttiUtil.find_type_info_vftable_label(program)
        if info_vftable_address is None:

            set = program.get_memory().get_loaded_and_initialized_address_set()
            data_blocks = ProgramMemoryUtil.get_memory_blocks_starting_with_name(program, set, ".data", monitor)

            vf_table_addr_checker = CommonRTTIMatchCounter(program)

            ProgramMemoryUtil.locate_string(CLASS_PREFIX_CHARS, vf_table_addr_checker, program, data_blocks, set, monitor)
            info_vftable_address = vf_table_addr_checker.info_vftable_address

        vftable_map[program] = info_vftable_address
        return info_vftable_address

    @staticmethod
    def find_type_info_vftable_label(program):
        symbol_table = program.get_symbol_table()

        typeinfo_namespace = symbol_table.get_namespace(RttiUtil.TYPE_INFO_NAMESPACE, program.get_global_namespace())

        vftable_symbol = symbol_table.get_local_variable_symbol("vftable", typeinfo_namespace)
        if vftable_symbol is not None:
            return vftable_symbol.address

        vftable_symbol = symbol_table.get_local_variable_symbol("`vftable'", typeinfo_namespace)
        if vftable_symbol is not None:
            return vftable_symbol.address

        try:
            vftable_symbol = symbol_table.create_label(address, "vftable", typeinfo_namespace, SourceType.IMPORTED)
            if vftable_symbol is None:
                Msg.error(RttiUtil.__class__, program.name + " Couldn't create type_info vftable symbol.")
                return
        except InvalidInputException as e:
            Msg.error(RttiUtil.__class__, program.name + " Couldn't create type_info vftable symbol. " + str(e))

    @staticmethod
    def create_type_info_vftable_symbol(program, address):
        symbol_table = program.get_symbol_table()

        typeinfo_namespace = symbol_table.get_namespace(RttiUtil.TYPE_INFO_NAMESPACE, program.get_global_namespace())

        if typeinfo_namespace is None:
            try:
                typeinfo_namespace = symbol_table.create_class(program.get_global_namespace(), RttiUtil.TYPE_INFO_NAMESPACE, SourceType.IMPORTED)
            except DuplicateNameException as e:
                Msg.error(RttiUtil.__class__, "Duplicate type_info class namespace at {}.".format(program.name), e)

        vftable_symbol = symbol_table.get_symbol(typeinfo_namespace, address, program.get_global_namespace())
        if vftable_symbol is not None:
            return

        symbols = symbol_table.get_symbols_as_iterator(address)
        for symbol in symbols:
            name = symbol.name
            if RttiUtil.TYPE_INFO_LABEL.casefold() in name.casefold():
                return  # Similar symbol already exists.

            source_type = symbol.source
            if source_type == SourceType.IMPORTED:
                return

        try:
            vftable_symbol = symbol_table.create_label(address, "vftable", typeinfo_namespace, SourceType.IMPORTED)
            if vftable_symbol is None:
                Msg.error(RttiUtil.__class__, program.name + " Couldn't create type_info vftable symbol.")
                return
        except InvalidInputException as e:
            Msg.error(RttiUtil.__class__, program.name + " Couldn't create type_info vftable symbol. " + str(e))
```

Note that I have not tested this code, and it may require additional modifications to work correctly in a Python environment.