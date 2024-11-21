Here is the translation of the given Java code into Python:

```Python
class InstructionSetTest:
    def __init__(self):
        self.instruction_set = None

    def addr(self, offset):
        return AddressSpace.DEFAULT_REGISTER_SPACE.get_address(offset)

    @classmethod
    def setUp(cls):
        b00 = create_block(cls.addr(0x00), 5)
        b10 = create_block(cls.addr(0x10), 5)
        b20 = create_block(cls.addr(0x20), 5)
        b30 = create_block(cls(addr(0x30)), 5)
        b40 = create_block(cls.addr(0x40), 5)
        b50 = create_block(cls.addr(0x50), 5)
        b60 = create_block(cls.addr(0x60), 5)
        b70 = create_block(cls.addr(0x70), 5)

        b00.add_branch_flow(b20.get_start_address())
        b00.add_branch_flow(b40.get_start_address())

        b10.set_flow_from_address(b30.get_last_instruction_address())
        b10.set_fall_through(b20.get_start_address())

        b20.set_flow_from_address(b00.get_last_instruction_address())
        b20.set_fall_through(b30.get_start_address())

        b30.set_flow_from_address(b20.get_last_instruction_address())
        b30.set_fall_through(b40.get_start_address())
        b30.add_branch_flow(b10.get_start_address())
        b30.add_branch_flow(b50.get_start_address())

        b40.set_flow_from_address(b30.get_last_instruction_address())

        b50.set_flow_from_address(b30.get_last_instruction_address())

        b70.add_branch_flow(b60.get_start_address())

        b60.set_flow_from_address(b70.get_last_instruction_address())

        self.instruction_set = InstructionSet(None)
        for block in [b00, b20, b30, b40, b10, b50, b70, b60]:
            self.instruction_set.add_block(block)

    def create_block(self, start, length):
        proto = InvalidPrototype(None)
        buf = ByteMemBufferImpl(start, bytearray(100), True)

        try:
            block = InstructionBlock(start)
            for i in range(length):
                addr = start + i
                instr = PseudoInstruction(addr, proto, buf, None)
                block.add_instruction(instr)
            return block
        except AddressOverflowException as e:
            assert False, "unexpected"

    @classmethod
    def test_basic_iterator(cls):
        it = cls.instruction_set.iterator()

        while it.has_next():
            next_block = it.next()
            if next_block.get_start_address() == cls.addr(0x00):
                continue

            if next_block.get_start_address() == cls.addr(0x20):
                continue
            elif next_block.get_start_address() == cls.addr(0x30):
                continue
            elif next_block.get_start_address() == cls.addr(0x40):
                continue
            elif next_block.get_start_address() == cls.addr(0x10):
                continue
            elif next_block.get_start_address() == cls.addr(0x50):
                continue
            elif next_block.get_start_address() == cls.addr(0x70):
                continue
            elif next_block.get_start_address() == cls.addr(0x60):
                break

        assert not it.has_next()

    @classmethod
    def test_block30_has_conflict(cls):
        it = cls.instruction_set.iterator()

        while it.has_next():
            next_block = it.next()
            if next_block.get_start_address() == cls.addr(0x00):
                continue
            elif next_block.get_start_address() == cls.addr(0x20):
                continue
            elif next_block.get_start_address() == cls.addr(0x30):
                next_block.set_instruction_error(
                    InstructionErrorType.INSTRUCTION_CONFLICT,
                    cls.addr(0x33),
                    cls(addr(0x34)),
                    None,
                    "Test conflict"
                )
                break

        while it.has_next():
            next_block = it.next()
            if next_block.get_start_address() == cls.addr(0x70):
                next_block.set_instruction_error(
                    InstructionErrorType.INSTRUCTION_CONFLICT,
                    cls(addr(0x73)),
                    cls(addr(0x74)),
                    None,
                    "Test conflict"
                )
                break

        assert not it.has_next()

    @classmethod
    def test_address_set(cls):
        results = AddressSet()
        for i in range(5):
            start = cls.addr(i * 8)
            end = start + 4
            results.add_range(start, end)

        assert results == cls.instruction_set.get_address_set()

    @classmethod
    def test_instruction_count(cls):
        assert cls.instruction_set.get_instruction_count() == 40

if __name__ == "__main__":
    InstructionSetTest().setUp()
```

Please note that this code is a direct translation of the given Java code into Python. It does not include any error handling or exception checking, as it was assumed to be part of the original Java code.