class DBTraceProgramViewProgramContext:
    def __init__(self, program):
        self.program = program
        self.language = program.language
        self.register_context_manager = program.trace.get_register_context_manager()
        self.default_context = self.register_context_manager.get_default_context(self.language)

    def get_registers_with_values(self):
        registers = self.language.get_registers()
        result = []
        for register in registers:
            for snap in reversed(list(self.program.viewport)):
                if self.register_context_manager.has_register_value(self.language, register, snap):
                    result.append(register)
                    break
        return [register for register in result]

    def get_value(self, register, address, signed=False):
        value = self.get_register_value(register, address)
        return value.signed_value() if signed else value.unsigned_value()

    @staticmethod
    def combine(value1, value2):
        if value1 is None:
            return value2
        elif value2 is None:
            return value1
        return value1.combine_values(value2)

    def stack(self, value, register, address):
        for snap in reversed(list(self.program.viewport)):
            value = self.combine(value, self.register_context_manager.get_value(self.language, register, snap, address))
        return value

    def get_register_value(self, register, address):
        value = self.register_context_manager.get_default_value(self.language, register, address)
        return self.stack(value, register, address)

    @staticmethod
    def set_register_value(start, end, value):
        if isinstance(value, RegisterValue):
            pass  # Do nothing for now
        else:
            raise ContextChangeException()

    def get_non_default_value(self, register, address):
        value = RegisterValue(register)
        return self.stack(value, register, address)

    @staticmethod
    def set_value(register, start, end, value):
        if isinstance(value, BigInteger) or isinstance(value, int):
            pass  # Do nothing for now
        else:
            raise ContextChangeException()

    class NestedAddressRangeIterator(AddressRangeIterator):
        def __init__(self, it, f):
            super().__init__(it, f)

        @staticmethod
        def iterator():
            return self

    def get_register_value_address_ranges(self, register):
        return AddressSetView.unioned_addresses(
            lambda s: self.register_context_manager.get_register_value_address_ranges(self.language, register, s)
        )

    def get_register_value_address_ranges(self, register, start, end):
        return NestedAddressRangeIterator(
            language.address_factory.get_address_set(start, end).iterator(),
            lambda range: AddressSetView.unioned_addresses(
                lambda s: self.register_context_manager.get_register_value_address_ranges(self.language, register, s, range)
            )
        )

    def get_register_value_range_containing(self, register, address):
        entry = self.register_context_manager.get_entry(self.language, register, self.program.snap, address)
        if entry is not None:
            return entry.key().get_range()
        # Compute the gap
        ranges = self.register_context_manager.get_register_value_address_ranges(self.language, register, self.program.snap)
        prev_it = ranges.addresses(address, False)
        min_addr = next(prev_it.next(), self.language.address_factory.min_address())
        next_it = ranges.addresses(address, True)
        max_addr = next(next_it.previous(), self.language.address_factory.max_address())
        return AddressRangeImpl(min_addr, max_addr)

    def get_default_register_value_address_ranges(self, register):
        return self.default_context.get_default_register_value_address_ranges(register)

    def get_default_register_value_address_ranges(self, register, start, end):
        return self.default_context.get_default_register_value_address_ranges(register, start, end)

    @staticmethod
    def remove(start, end, register):
        try:
            with LockHold(self.program.trace.lock_write()):
                span = Range.closed(self.program.snap, self.program.snap)
                for range in language.address_factory.get_address_set(start, end):
                    self.register_context_manager.remove_value(
                        self.language,
                        register,
                        span,
                        range
                    )
        except ContextChangeException:
            pass

    def has_value_over_range(self, register, value, address_set):
        reg_val = RegisterValue(register, value)
        with LockHold(self.program.trace.lock_read()):
            remains = AddressSet(address_set)
            while not remains.is_empty():
                to_remove = AddressSet()
                for range in remains:
                    entry = self.register_context_manager.get_entry(
                        self.language,
                        register,
                        self.program.snap,
                        range.min_address
                    )
                    if entry is None:
                        return False
                    if reg_val != entry.value:
                        return False
                    to_remove.add(entry.key().get_range())
                remains.delete(to_remove)
        return True

    def get_default_value(self, register, address):
        return self.default_context.get_default_value(register, address)

    @staticmethod
    def get_disassembly_context(address):
        value = self.get_register_value(base_context_register, address)
        if value is not None:
            return value
        return self.default_context.get_disassembly_context(address)

    @staticmethod
    def set_default_value(register_value, start, end):
        raise UnsupportedOperationException()
