Here is the translation of the Java code into Python:

```Python
class PCodeTestAbstractControlBlock:
    def __init__(self, program: 'Program', info_struct_addr: Address, info_program_struct: Structure):
        self.program = program
        self.pointer_size = program.get_data_type_manager().get_pointer_size()
        self.info_struct_addr = info_struct_addr
        self.info_program_struct = info_program_struct.clone(program.get_data_type_manager())
        
        self.code_space = program.get_address_factory().get_default_address_space()
        self.data_space = program.get_language().get_default_data_space()

        self.disassembler = Disassembler.get_disassembler(self.program, TaskMonitor.DUMMY)

    def get_info_structure_address(self) -> Address:
        return self.info_struct_addr

    def get_function_info(self, function_name: str) -> 'FunctionInfo':
        return self.function_map[function_name]

    def get_function_info(self, function_index: int) -> 'FunctionInfo':
        return self.functions[function_index]

    def get_number_functions(self) -> int:
        return len(self.functions)

    @staticmethod
    def get_char_array_bytes(program: 'Program', string: str):
        data_organization = program.get_data_type_manager().get_data_organization()
        char_size = data_organization.get_char_size()

        if char_size == 1:
            return bytes(string.encode())

        # generate aligned byte array
        len_ = char_size * len(string)
        bytes_array = bytearray(len_)
        big_endian = program.get_memory().is_big_endian()
        index = 0
        pad = char_size - 1

        for str_byte in string.encode():
            if big_endian:
                index += pad
            bytes_array[index] = str_byte
            if not big_endian:
                index += pad
            index += 1

        return bytes_array

    def read_pointer(self, buffer: 'MemBuffer', offset: int, address_space: AddressSpace) -> Address:
        pointer_size = self.pointer_size
        bytes_array = bytearray(pointer_size)
        buffer.get_bytes(bytes_array, offset)

        long_offset = Utils.bytes_to_long(bytes_array, pointer_size, buffer.is_big_endian())
        return address_space.get_address(long_offset * address_space.get_addressable_unit_size())

    def read_defined_data_pointer(self, addr: Address) -> Address:
        data = self.program.get_listing().get_defined_data_at(addr)
        if data is None or not isinstance(data, Pointer):
            return None
        return data.get_value()

    def read_code_pointer(self, buffer: 'MemBuffer', offset: int, update_reference: bool) -> Address:
        code_ptr = self.read_pointer(buffer, offset, self.code_space)

        # treat null pointer as special case - just return it
        if code_ptr.get_offset() == 0:
            return code_ptr

        # shift the pointer if code pointers are stored in memory shifted.
        ptr_shift = self.program.get_data_type_manager().get_data_organization().get_pointer_shift()
        if ptr_shift != 0:
            code_ptr = code_ptr.new_address(code_ptr.get_offset() << ptr_shift)

        # Check for potential procedure descriptor indirection (e.g., PPC64 .opd)
        # in which case a function pointer may refer to a procedure descriptor
        # record (we assume here that the first entry has been marked-up by the importer
        # and corresponds to the true function address

        addr = self.read_defined_data_pointer(code_ptr)

        if addr is not None:
            return addr
        else:
            code_block = self.disassembler.pseudo_disassemble_block(addr, None, 1)
            if code_block is None or code_block.is_empty() or code_block.has_instruction_error():
                raise MemoryAccessException("Code pointer " + str(code_ptr) + " does not refer to valid code")

            # TODO: may need to handle more complex thunks
            instruction = code_block.get_instruction_at(addr)
            flow_type = instruction.get_flow_type()
            if flow_type.is_jump():
                flows = instruction.get_flows()
                if len(flows) == 1:
                    return flows[0]

    def read_data_pointer(self, buffer: 'MemBuffer', offset: int, update_reference: bool) -> Address:
        return self.read_pointer(buffer, offset, self.data_space)

    # ... rest of the class ...

class InvalidControlBlockException(Exception):
    pass

class FunctionInfo:
    def __init__(self, function_name: str, function_addr: Address, number_of_asserts: int):
        self.function_name = function_name
        self.function_addr = function_addr
        self.number_of_asserts = number_of_asserts

    @staticmethod
    def compare(other) -> int:
        return self.function_name.compare(other.function_name)

    def __eq__(self, other) -> bool:
        if not isinstance(other, FunctionInfo):
            return False
        return self.function_name == other.function_name and self.function_addr == other.function_addr

    def __hash__(self) -> int:
        return self.function_addr.hash()

    def __str__(self) -> str:
        return f"{self.function_name}@{self.function_addr}"
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code might have some specific requirements or assumptions that are not directly translatable to Python.