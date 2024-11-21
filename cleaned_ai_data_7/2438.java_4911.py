class DBTraceProgramViewRegisterMemory:
    def __init__(self, program: 'DBTraceProgramView', space: 'DBTraceMemoryRegisterSpace'):
        self.space = space
        self.block = DBTraceProgramViewRegisterBlock(program, space)
        super().__init__(program)

    @property
    def address_set(self):
        return AddressSet(AddressRangeImpl(self.space.get_address_space().get_min_address(), 
                                            self.space.get_address_space().get_max_address()))

    def recompute_address_set(self):
        # AddressSet is always full space

    def get_block(self, addr: 'Address'):
        if addr.get_address_space().is_register_space():
            return self.block
        return None

    def get_block(self, block_name: str) -> 'MemoryBlock':
        if DBTraceProgramViewRegisterMemoryBlock.REGS_BLOCK_NAME == block_name:
            return self.block
        return None

    def get_blocks(self):
        # NOTE: Don't cache, to avoid external mutation.
        return [self.block]
