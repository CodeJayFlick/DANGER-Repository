class PseudoInstruction:
    def __init__(self, program=None, address=None, prototype=None, mem_buffer=None, proc_context=None):
        super().__init__()
        self.instr_proto = prototype
        if program is not None:
            self.addr_factory = program.get_address_factory()
        else:
            self.addr_factory = None

        self.block = None  # may be null
        self.proc_context = proc_context
        self.parser_context = None
        self.flow_override = FlowOverride.NONE
        self.fall_through_override = None  # NO_ADDRESS indicate fall-through removed

    def get_byte_cache_size(self, prototype):
        length = prototype.get_length()
        delay_slot_byte_count = prototype.get_delay_slot_byte_count()

        if delay_slot_byte_count == 1:
            # Assume this is a minimum size and cache enough for one more instruction of the same size.
            return length + length
        else:
            # NOTE: This may have a problem if delaySlotByteCount is a minimum byte count and more bytes are needed for delay slots.
            return length + delay_slot_byte_count

    def get_repeated_byte(self):
        self.refresh_if_needed()
        b0 = self.bytes[0]
        if len(self) == 1:
            return b0
        else:
            for i in range(1, len(self)):
                if self.bytes[i] != b0:
                    return None

    def get_base_register(self):
        return self.proc_context.get_base_register()

    def get_operand_references(self, op_index):
        to_addr = self.instr_proto.get_address(op_index, self)
        if to_addr is None:
            return [self.empty_mem_ref]
        ref = MemReferenceImpl(to_addr, self.address, self.get_operand_ref_type(op_index), SourceType.DEFAULT, op_index, False)
        return [ref]

    def __eq__(self, other):
        if not isinstance(other, PseudoInstruction):
            return NotImplemented
        if hash(self) != hash(other):
            return False

        if self.address != other.address:
            return False

        return self.instr_proto == other.instr_proto

    def get_prototype(self):
        return self.instr_proto

    # ... and so on for the rest of the methods.
