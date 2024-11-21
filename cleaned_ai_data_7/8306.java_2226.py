class TrampolineMsSymbol:
    PDB_ID = 0x112c
    
    class Type(enum.Enum):
        UNKNOWN = ("unknown subtype", -1)
        INCREMENTAL = "Incremental", 0
        BRANCH_ISLAND = "BranchIsland", 1
        
        BY_VALUE = {value: value_name for value_name, (value, _) in enumerate(Type)}
        
        def __init__(self, label, value):
            self.label = label
            self.value = value
            
        def __str__(self):
            return self.label
        
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.trampoline_type = TrampolineMsSymbol.Type(reader.read_uint16())
        self.size_of_thunk = reader.read_uint16()
        self.offset_thunk = reader.read_uint32()
        self.offset_target = reader.read_uint32()
        self.section_thunk = pdb.parse_segment(reader)
        self.section_target = pdb.parse_segment(reader)

    def get_pdb_id(self):
        return TrampolineMsSymbol.PDB_ID

    @property
    def type(self):
        return self.trampoline_type
    
    @property
    def size_of_thunk(self):
        return self.size_of_thunk
    
    def get_offset(self):
        return self.get_offset_thunk()

    def get_segment(self):
        return self.get_segment_thunk()
    
    @property
    def offset_thunk(self):
        return self.offset_thunk

    @property
    def offset_target(self):
        return self.offset_target

    @property
    def segment_thunk(self):
        return self.section_thunk
    
    @property
    def segment_target(self):
        return self.section_target

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: subtype {self.trampoline_type}, code size = {self.size_of_thunk} bytes\n")
        builder.append(f"   Thunk address: [{self.segment_thunk}:{self.offset_thunk}\n"]
        builder.append(f"   Thunk target:   [{self.segment_target}:{self.offset_target}\n"]

    def get_symbol_type_name(self):
        return "TRAMPOLINE"
