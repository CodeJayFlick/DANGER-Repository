class DWARFRegisterMappings:
    DUMMY = DWARFRegisterMappings({}, -1, -1, False)

    def __init__(self, regmap: dict, call_frame_cfa: int, stack_pointer_index: int, use_formal_parameter_storage: bool):
        self.dwarf_register_map = regmap
        self.call_frame_cfa = call_frame_cfa
        self.stack_pointer_index = stack_pointer_index
        self.use_formal_parameter_storage = use_formal_parameter_storage

    def get_ghidra_reg(self, dwarf_reg_num: int) -> 'Register':
        return self.dwarf_register_map.get(dwarf_reg_num)

    def get_call_frame_cfa(self) -> int:
        return self.call_frame_cfa

    def get_dwarf_stack_pointer_reg_num(self) -> int:
        return self.stack_pointer_index

    def is_use_formal_parameter_storage(self) -> bool:
        return self.use_formal_parameter_storage

    def __str__(self):
        return f"DWARFRegisterMappings [dwarf_register_map={self.dwarf_register_map}, call_frame_cfa={self.call_frame_cfa}, stack_pointer_index={self.stack_pointer_index}, use_formal_parameter_storage={self.use_formal_parameter_storage}]"
