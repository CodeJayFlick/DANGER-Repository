Here is a translation of the Java code into equivalent Python:

```Python
class MzLoader:
    def __init__(self):
        pass

    @staticmethod
    def get_tier_priority():
        return 60

    def find_supported_load_specs(self, provider) -> list:
        load_specs = []
        
        if len(provider.get_bytes()) < MIN_BYTE_LENGTH:
            return load_specs
        
        ose = OldStyleExecutable(RethrowContinuesFactory.INSTANCE, provider)
        dos_header = ose.get_dos_header()
        
        if dos_header.is_dos_signature() and not dos_header.has_new_exe_header() and not dos_header.has_pe_header():
            results = QueryOpinionService.query(self.name(), str(dos_header.e_magic()), None)
            
            for result in results:
                load_specs.append(LoadSpec(self, 0, result))
                
            if len(load_specs) == 0:
                load_specs.append(LoadSpec(self, 0, True))
        
        return load_specs

    def load(self, provider: ByteProvider, load_spec: LoadSpec, options: list[Option], program: Program, 
             monitor: TaskMonitor, log: MessageLog):
        file_bytes = MemoryBlockUtils.create_file_bytes(program, provider, monitor)
        address_factory = program.get_address_factory()
        
        if not isinstance(address_factory.get_default_address_space(), SegmentedAddressSpace):
            raise IOException("Selected Language must have a segmented address space.")
        
        space = (SegmentedAddressSpace)address_factory.get_default_address_space()
        symbol_table = program.get_symbol_table()
        context = program.get_program_context()
        memory = program.get_memory()

        factory = MessageLogContinuesFactory.create(log)
        ose = OldStyleExecutable(factory, provider)
        dos_header = ose.get_dos_header()
        
        reader = ose.get_binary_reader()
        
        if monitor.is_cancelled():
            return
        
        monitor.set_message("Processing segments...")
        self.process_segments(program, file_bytes, space, reader, dos_header, log, monitor)

        if monitor.is_cancelled():
            return
        
        monitor.set_message("Adjusting segments...")
        self.adjust_segment_starts(program)
        
        if monitor.is_cancelled():
            return
        
        monitor.set_message("Processing relocations...")
        self.do_relocations(program, reader, dos_header)
        
        if monitor.is_cancelled():
            return
        
        monitor.set_message("Processing symbols...")
        self.create_symbols(space, symbol_table, dos_header)

        if monitor.is_cancelled():
            return
        
        monitor.set_message("Setting registers...")
        self.set_registers(context, memory.get_blocks(), dos_header)

    def set_registers(self, context: ProgramContext, entry_symbol: Symbol, blocks: list[MemoryBlock], 
                      dos_header: DOSHeader):
        # your code here

    def adjust_segment_starts(self, program: Program):
        mem = program.get_memory()
        
        if not program.has_exclusive_access():
            return
        
        for block in mem.get_blocks():
            if not block.is_initialised():
                continue
            
            m_index = 15
            if len(block) <= 16:
                m_index = (len(block) - 2)
            
            for i in range(m_index, -1, -1):
                try:
                    off_addr = block.get_address(i)
                    val = block.get_byte(off_addr)
                    
                    # your code here

    def process_segments(self, program: Program, file_bytes: FileBytes, space: SegmentedAddressSpace, 
                          reader: FactoryBundledWithBinaryReader, dos_header: DOSHeader, log: MessageLog, monitor: TaskMonitor):
        try:
            relocation_table_offset = Conv.short_to_int(dos_header.e_lfarlc())
            cs_start = INITIAL_SEGMENT_VAL
            data_start = dos_header.e_cparhdr() << 4
            
            num_relocation_entries = dos_header.e_crlc()
            
            reader.set_pointer_index(relocation_table_offset)
            
            for i in range(num_relocation_entries):
                off = Conv.short_to_int(reader.read_next_short())
                seg = Conv.short_to_int(reader.read_next_short())

                # your code here

    def do_relocations(self, program: Program, reader: FactoryBundledWithBinaryReader, dos_header: DOSHeader):
        try:
            mem = program.get_memory()
            
            relocation_table_offset = Conv.short_to_int(dos_header.e_lfarlc())
            cs_start = INITIAL_SEGMENT_VAL
            data_start = dos_header.e_cparhdr() << 4
            
            num_relocation_entries = dos_header.e_crlc()
            
            reader.set_pointer_index(relocation_table_offset)
            
            for i in range(num_relocation_entries):
                off = Conv.short_to_int(reader.read_next_short())
                seg = Conv.short_to_int(reader.read_next_short())

    def create_symbols(self, space: SegmentedAddressSpace, symbol_table: SymbolTable, dos_header: DOSHeader):
        ip_value = Conv.short_to_int(dos_header.e_ip())
        code_segment = Conv.short_to_int(dos_header.e_cs()) + INITIAL_SEGMENT_VAL

        if code_segment > Conv.SHORT_MASK:
            print("Invalid entry point location:", hex(code_segment), ":", hex(ip_value))
            return
        
        addr = space.get_address(code_segment, ip_value)

        try:
            symbol_table.create_label(addr, ENTRY_NAME, SourceType.IMPORTED)
        except InvalidInputException as e:
            # Just skip if we can't create
            pass

        symbol_table.add_external_entry_point(addr)

    @staticmethod
    def get_name():
        return MZ_NAME


class LoadSpec:
    def __init__(self, loader: MzLoader, priority: int, result):
        self.loader = loader
        self.priority = priority
        self.result = result

class OldStyleExecutable:
    def __init__(self, factory: ContinuesFactory, provider: ByteProvider):
        pass
    
    def get_dos_header(self) -> DOSHeader:
        return None
    
    def get_binary_reader(self) -> FactoryBundledWithBinaryReader:
        return None


MIN_BYTE_LENGTH = 4
INITIAL_SEGMENT_VAL = 0x1000
FAR_RETURN_OPCODE = 0xCB
MOVW_DS_OPCODE = (byte) 0xBA

class DOSHeader:
    def __init__(self):
        pass
    
    @property
    def is_dos_signature(self) -> bool:
        return False
    
    @property
    def has_new_exe_header(self) -> bool:
        return False
    
    @property
    def has_pe_header(self) -> bool:
        return False

    @property
    def e_magic(self):
        pass

    @property
    def e_lfarlc(self) -> int:
        pass

    @property
    def e_crlc(self) -> int:
        pass
    
    @property
    def e_ip(self) -> int:
        pass

    @property
    def e_cs(self) -> int:
        pass


class SegmentedAddressSpace:
    pass


class SymbolTable:
    def __init__(self):
        pass
    
    def create_label(self, addr: Address, name: str, source_type: SourceType):
        pass
    
    def add_external_entry_point(self, addr: Address):
        pass

class ProgramContext:
    pass

class MemoryBlockUtils:
    @staticmethod
    def create_file_bytes(program: Program, provider: ByteProvider, monitor: TaskMonitor) -> FileBytes:
        return None


MIN_BYTE_LENGTH = 4