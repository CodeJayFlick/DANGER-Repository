Here is the translation of the Java code into Python:

```Python
class RttiAnalyzer:
    def __init__(self):
        self.name = "Windows x86 PE RTTI Analyzer"
        self.description = "Finds and creates RTTI metadata structures and associated vf tables."
        self.class_prefix_chars = ".?A"

    def can_analyze(self, program):
        return PEUtil.is_visual_studio_or_clang_pe(program)

    def added(self, program, address_set_view, task_monitor, message_log):
        common_vf_table_address = RttiUtil.find_type_info_vftable_address(program, task_monitor)
        
        if common_vf_table_address is None:
            return True
        
        RttiUtil.create_type_info_vftable_symbol(program, common_vf_table_address)

        possible_type_addresses = self.locate_potential_rtti0_entries(program, address_set_view, task_monitor)
        
        if possible_type_addresses is None:
            return True

        for rtti0_address in possible_type_addresses:
            monitor.check_canceled()
            try:
                type_model = TypeDescriptorModel(program, rtti0_address, self.validation_options)
                if not isinstance(type_model.get_type_name(), str) or not type_model.get_type_name().startswith(self.class_prefix_chars):
                    continue
            except InvalidDataTypeException as e:
                continue

            create_type_descriptor_background_cmd = CreateTypeDescriptorBackgroundCmd(rtti0_address, self.validation_options, self.apply_options)
            create_type_descriptor_background_cmd.apply_to(program, task_monitor)

        self.process_rtti4s_for_rtti0(program, possible_type_addresses, task_monitor)

    def locate_potential_rtti0_entries(self, program, address_set_view, task_monitor):
        common_vf_table_address = RttiUtil.find_type_info_vftable_address(program, task_monitor)
        
        if common_vf_table_address is None:
            return None

        data_blocks = ProgramMemoryUtil.get_memory_blocks_starting_with_name(program, program.memory(), ".data", task_monitor)

        possible_type_addresses = ProgramMemoryUtil.find_direct_references(program, data_blocks, 4, common_vf_table_address, task_monitor)
        
        return possible_type_addresses

    def process_rtti0(self, rtti0_locations):
        for address in rtti0_locations:
            try:
                type_model = TypeDescriptorModel(address, self.validation_options)
                if not isinstance(type_model.get_type_name(), str) or not type_model.get_type_name().startswith(self.class_prefix_chars):
                    continue
            except InvalidDataTypeException as e:
                continue

            create_type_descriptor_background_cmd = CreateTypeDescriptorBackgroundCmd(address, self.validation_options, self.apply_options)
            create_type_descriptor_background_cmd.apply_to()

    def process_rtti4s_for_rtti0(self, program, rtti0_locations, task_monitor):
        data_blocks = ProgramMemoryUtil.get_memory_blocks_starting_with_name(program, program.memory(), ".rdata", task_monitor) + \
                      ProgramMemoryUtil.get_memory_blocks_starting_with_name(program, program.memory(), ".data", task_monitor) + \
                      ProgramMemoryUtil.get_memory_blocks_starting_with_name(program, program.memory(), ".text", task_monitor)

        rtti4_addresses = self.get_rtti4_addresses(program, data_blocks, rtti0_locations, self.validation_options, task_monitor)
        
        if len(rtti4_addresses) > 0:
            create_rtti4_background_cmd = CreateRtti4BackgroundCmd(rtti4_addresses, data_blocks, self.validation_options, self.apply_options)
            create_rtti4_background_cmd.apply_to(program, task_monitor)

    def get_rtti4_addresses(self, program, rtti4_blocks, rtti0_locations, validation_options, task_monitor):
        addresses = []
        
        for address in rtti0_locations:
            bytes = ProgramMemoryUtil.get_direct_address_bytes(program, address)
            
            if len(bytes) > 0:
                add_byte_search_pattern(searcher, validation_options, addresses, rtti0_pointer_offset, address, bytes)

        return addresses

    def get_refs_to_rtti0(self, program, data_blocks, rtti0_locations):
        addresses = []
        
        for address in rtti0_locations:
            if MSDataTypeUtils.is_64_bit(program):
                bytes = ProgramMemoryUtil.get_image_base_offsets32_bytes(program, 4, address)
                
                add_byte_search_pattern(searcher, validation_options, addresses, rtti0_pointer_offset, address, bytes)

    def add_byte_search_pattern(self, searcher, validation_options, addresses, rtti0_pointer_offset, address, bytes):
        action = GenericMatchAction(address) {
            apply: (program, addr, match) => 
                possible_rtti4_address = addr.subtract_no_wrap(rtti0_pointer_offset)
                
                if isinstance(possible_rtti4_address, int):
                    return
                rtti4_model = Rtti4Model(program, possible_rtti4_address, validation_options)
                    
                    try:
                        rtti4_model.validate()
                    except InvalidDataTypeException as e:
                        return

    def apply(self, program, task_monitor):
        pass