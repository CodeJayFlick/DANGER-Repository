class ProgramByteBlockSet:
    def __init__(self, provider: 'ProgramByteViewerComponentProvider', program: 'Program', bbcm=None):
        self.provider = provider
        self.program = program
        if bbcm is None:
            self.bbcm = ByteBlockChangeManager(self)
        else:
            self.bbcm = ByteBlockChangeManager(self, bbcm)

        self.new_memory_blocks()

    def get_blocks(self) -> list['ByteBlock']:
        return self.blocks

    def get_plugin_event(self, source: str, selection: 'ByteBlockSelection') -> 'ProgramSelectionPluginEvent':
        addr_set = AddressSet()
        for i in range(selection.get_number_of_ranges()):
            br = selection.get_range(i)
            block = br.get_byte_block()
            start_addr = self.get_address(block, br.get_start_index())
            end_addr = self.get_address(block, br.get_end_index())
            addr_set.add(AddressRangeImpl(start_addr, end_addr))
        return ProgramSelectionPluginEvent(source, ProgramSelection(addr_set), self.program)

    def get_plugin_event(self, source: str, block: 'ByteBlock', offset: int | None, column: int) -> 'ProgramLocationPluginEvent':
        loc = self.provider.get_location(block, offset, column)
        return ProgramLocationPluginEvent(source, loc, self.program)

    def process_byte_block_change_event(self, event: 'ByteBlockChangePluginEvent'):
        if event.get_program() == self.program:
            self.bbcm.add(event.get_byte_edit_info())

    def collect_block_selection(self, range: AddressRange, result: list['ByteBlockRange']):
        for i in range(len(self.blocks)):
            block_start = self.mem_blocks[i].get_start()
            block_end = self.mem_blocks[i].get_end()
            intersection = range.intersect(AddressRangeImpl(block_start, block_end))
            if intersection is not None:
                start_info = self.get_byte_block_info(intersection.min_address)
                end_info = self.get_byte_block_info(intersection.max_address)
                br = ByteBlockRange(start_info.block, start_info.offset, end_info.offset)
                result.append(br)

    def get_block_selection(self, range: AddressRange) -> 'ByteBlockSelection':
        list_ = []
        self.collect_block_selection(range, list_)
        return ByteBlockSelection(list_)

    def is_changed(self, block: 'ByteBlock', index: int | None, length: int) -> bool:
        return self.bbcm.is_changed(block, index, length)

    def set_byte_block_change_manager(self, bbcm: 'ByteBlockChangeManager'):
        self.bbcm = bbcm

    def notify_byte_editing(self, block: 'ByteBlock', index: int | None, old_value: bytes, new_value: bytes):
        edit = ByteEditInfo(get_address(block, BigInteger.ZERO), index, old_value, new_value)
        self.bbcm.add(edit)
        self.provider.notify_edit(edit)

    def get_undo_redo_state(self) -> 'SaveState':
        return self.bbcm.get_undo_redo_state()

    def restore_undo_redo_state(self, save_state: 'SaveState'):
        self.bbcm.restore_undo_redo_state(save_state)

    @property
    def byte_block_change_manager(self):
        return self.bbcm

    def get_address(self, block: 'ByteBlock', offset: int | None) -> Address:
        for i in range(len(self.blocks)):
            if self.blocks[i] != block:
                continue
            try:
                addr = self.mem_blocks[i].get_start()
                return addr.add_no_wrap(offset)
            except AddressOverflowException as e:
                raise IndexOutOfBoundsException(f"Offset {offset} is not in this block") from e

    def get_byte_block_info(self, address: Address) -> 'ByteBlockInfo':
        if not self.program.get_memory().contains(address):
            # this block set is out of date...eventually a new
            # ProgramByteBlockSetImpl will be created
            return None

        for i in range(len(self.blocks)):
            if not self.mem_blocks[i].contains(address):
                continue
            try:
                off = address.subtract(self.mem_blocks[i].get_start())
                offset = BigInteger(off) if off < 0 else BigInteger(off)
                return ByteBlockInfo(self.blocks[i], offset)
            except Exception as e:
                return None

        return None

    def get_block_start(self, block: 'ByteBlock') -> Address:
        return self.get_address(block, BigInteger.ZERO)

    def get_block_start(self, block_number: int) -> Address:
        return self.mem_blocks[block_number].get_start()

    def get_byte_block_number(self, address: Address) -> int:
        for i in range(len(self.mem_blocks)):
            if self.mem_blocks[i].get_start().compareTo(address) == 0:
                return i
        return -1

    @property
    def address_set(self):
        addr_set = AddressSet()
        for _ in range(selection.get_number_of_ranges()):
            br = selection.get_range(i)
            block = br.get_byte_block()
            start_addr = self.get_address(block, br.get_start_index())
            end_addr = self.get_address(block, br.get_end_index())
            addr_set.add(AddressRangeImpl(start_addr, end_addr))
        return addr_set

    def new_memory_blocks(self):
        memory = self.program.get_memory()
        self.mem_blocks = memory.get_blocks()
        self.blocks = [new_memory_byte_block(memory, mem_block) for mem_block in self.mem_blocks]

    @staticmethod
    def new_memory_byte_block(memory: 'Memory', mem_block: 'MemoryBlock') -> 'ByteBlock':
        return MemoryByteBlock(self.program, memory, mem_block)

    def dispose(self):
        # nothing to do?!?!?
        pass

    def start_transaction(self) -> int:
        return self.program.start_transaction("Memory Edit")

    def end_transaction(self, transaction_id: int, b: bool):
        self.program.end_transaction(transaction_id, b)
