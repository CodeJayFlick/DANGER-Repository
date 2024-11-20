class TableEntry:
    def __init__(self, program: 'Program', table_entry_address: 'TableEntryAddress', entry_size: int, sign_extend: bool):
        self.program = program
        self.table_entry_address = table_entry_address
        self.size = entry_size
        self.sign_extend = sign_extend

    @property
    def get_table_entry_size(self) -> int:
        return self.size


class TableEntryAddress:
    @staticmethod
    def get_case_address(case_index_value: int, program: 'Program') -> Address:
        # implementation of this method is not provided in the Java code
        pass

    @property
    def get_index_value(self) -> Varnode:
        return self.index_value


class Program:
    def __init__(self):
        pass

    def create_data(self, listing: 'Listing', entry_addr: Address):
        # implementation of this method is not provided in the Java code
        pass

    @property
    def get_address_factory(self) -> 'AddressFactory':
        return self.address_factory


class Varnode:
    def __init__(self):
        pass

    @property
    def get_pcode_op(self) -> PcodeOp:
        return self.pcode_op


def create_data(program: Program, listing: Listing, entry_addr: Address):
    # implementation of this method is not provided in the Java code
    pass


class ShiftedAddressDataType(DataType):
    @staticmethod
    def data_type() -> 'ShiftedAddressDataType':
        return ShiftedAddressDataType()


class PointerDataType(DataType):
    @staticmethod
    def get_pointer(data_type: DataType, size: int) -> 'PointerDataType':
        return PointerDataType()


def create_pointer(entry_addr: Address, scaleFactor: int):
    # implementation of this method is not provided in the Java code
    pass


def get_long_value(program: Program, entry_addr: Address, scaleFactor: int, size: int, sign_extend: bool) -> long:
    bytes = bytearray(size)
    try:
        program.get_memory().get_bytes(entry_addr, bytes)
    except MemoryAccessException as e:
        print(f"Failed to read table entry at {entry_addr}: {e}")
        return 0
    val = 0
    if program.get_language().is_big_endian():
        for i in range(size):
            val = (val << 8) + int.from_bytes(bytes[i:i+1], 'big')
        if sign_extend and bytes[0] < 0:
            val = -1
    else:
        for i in range(size-1, -1, -1):
            val = (val << 8) + int.from_bytes(bytes[i:i+1], 'little')
        if sign_extend and bytes[size-1] < 0:
            val = -1
    return val * scaleFactor


def get_table_entry(program: Program, v: Varnode) -> TableEntry or None:
    if not isinstance(v, VarnodeOperation):
        return None
    op = (VarnodeOperation)v
    opcode = op.get_pcode_op().get_opcode()
    sign_extend = False
    if opcode == PcodeOp.INT_SEXT or opcode == PcodeOp.INT_ZEXT:
        v = op.get_input_values()[0]
        sign_extend = opcode == PcodeOp.INT_SEXT
        if not isinstance(v, VarnodeOperation):
            return None
        op = (VarnodeOperation)v
    if opcode != PcodeOp.LOAD:
        return None
    input_values = op.get_input_values()
    if not input_values[0].is_constant():
        return None
    addr_factory = program.get_address_factory()
    table_entry_address = TableEntryAddress.get_table_entry_address(addr_factory, input_values[1])
    if table_entry_address is None:
        return None
    return TableEntry(program, table_entry_address, op.get_size(), sign_extend)
