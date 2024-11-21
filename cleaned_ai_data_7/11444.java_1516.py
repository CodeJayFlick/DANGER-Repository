class ProgramStructureProviderContext:
    def __init__(self, program: 'Program', loc):
        self.program = program
        data_path = list(loc.get_component_path())
        data = program.get_listing().get_defined_data_containing(loc.get_address())
        data = data.get_component(data_path)
        self.addr = data.get_min_address()
        my_offset = data.get_parent_offset()
        parent_data = data.get_parent()
        struct = parent_data.get_data_type()
        
    def __init__(self, program: 'Program', addr: int, struct: object, my_offset: int):
        self.program = program
        self.addr = addr
        self.struct = struct
        self.myoffset = my_offset

    def get_data_type_component(self, offset: int) -> object:
        poffset = self.myoffset + offset
        
        if poffset < 0 or poffset >= len(struct):
            return None
            
        return struct[poffset]

    def get_data_type_components(self, start: int, end: int) -> list:
        result = []
        for offset in range(start, end+1):
            dtc = self.get_data_type_component(offset)
            if dtc is None:
                break
            result.append(dtc)
            offset += len(dtc)

        return [x for x in result]

    def get_unique_name(self, base_name: str) -> str:
        return self.program.get_listing().get_data_type_manager().get_unique_name(CategoryPath.ROOT, base_name)
