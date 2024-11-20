Here is the translation of the Java code into Python:

```Python
class PdbVbtManager:
    def __init__(self, applicator):
        self.address_by_mangled_name = {}
        self.memory = get_memory(applicator)
        try:
            address_by_mangled_name = find_virtual_base_table_symbols(applicator)
        except CancelledException as e:
            print(f"Cancelled: {e}")
        
    def create_virtual_base_tables(self):
        for entry in self.address_by_mangled_name.items():
            address, mangled_name = entry
            if not is_invalid_address(address, mangled_name):
                vbt = PdbVirtualBaseTable(self.memory, address)
                self.vbts[address] = vbt

    def create_virtual_base_table(self, address):
        return PdbVirtualBaseTable(self.memory, address)

    def get_offset(self, vbt_mangled_name, ordinal, size):
        if not is_invalid_address(vbt_mangled_name):
            raise Exception(f"Cannot find address for table name: {vbt_mangled_name}")
        return self.vbts[address].get_entry(ordinal).offset

class PdbVirtualBaseTable:
    def __init__(self, memory, address):
        super().__init__()
        self.memory = memory
        self.address = address
    
    def get_entry(self, ordinal):
        if not is_invalid_address(address):
            raise Exception(f"Cannot find entry for table name: {address}")
        return parse_vbt_entry_from_memory(memory, address, ordinal)

def get_memory(applicator):
    program = applicator.get_program()
    if program == None:
        raise PdbException("Program null for VbtManager")
    return program.memory

def find_virtual_base_table_symbols(applicator):
    monitor = applicator.get_monitor()
    symbol_group = applicator.get_symbol_group()
    address_by_mangled_name = {}
    
    public_symbol_information = applicator.get_pdb().get_debug_info().get_public_symbol_information()
    offsets = public_symbol_information.get_modified_hash_record_symbol_offsets()
    applicator.set_monitor_message("PDB: Searching for virtual base table symbols...")
    monitor.initialize(len(offsets))
    
    iter = symbol_group.iterator()
    for offset in offsets:
        monitor.check_cancelled()
        if not iter.has_next():
            break
        symbol = iter.peek()
        if isinstance(symbol, AbstractPublicMsSymbol):
            name = symbol.name
            if name.startswith("??_8"):
                address = applicator.get_address(symbol)
                if not is_invalid_address(address, name):
                    address_by_mangled_name[name] = address
                monitor.increment_progress(1)

    return address_by_mangled_name

def parse_vbt_entry_from_memory(memory, address, ordinal, size):
    read_address = address + (ordinal * size)
    try:
        offset = memory.get_long(read_address) if size == 8 else memory.get_int(read_address)
    except MemoryAccessException as e:
        raise PdbException(f"MemoryAccessException while trying to parse virtual base table entry at address: {read_address}")
    
    return VirtualBaseTableEntry(offset)

class VirtualBaseTableEntry:
    def __init__(self, offset):
        self.offset = offset

def is_invalid_address(address, name):
    # implement your logic here
    pass
```

Please note that this translation does not include the exact equivalent of Java's `PdbException` class in Python. You can use Python's built-in exception classes or create a custom one if needed.

Also, some methods like `get_program`, `get_monitor`, and others are missing their implementations as they seem to be part of another class (like `PdbApplicator`).