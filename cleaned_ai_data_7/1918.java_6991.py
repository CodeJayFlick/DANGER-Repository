class AbstractModelForLldbX64RegistersTest:
    REG_VALS = {"rax": bytearray(b"0123456789abcdef"), "mm0": bytearray(b"0123456789abcdef")}

    def get_test(self):
        return self

    def is_register_bank_also_container(self):
        return False

    def get_expected_register_bank_path(self, thread_path):
        return PathUtils.extend(thread_path, ["Stack[0].Registers"])

    def get_register_writes(self):
        return REG_VALS.copy()

    def get_launch_specimen(self):
        return MacOSSpecimen.PRINT

    @staticmethod
    def test_registers_have_expected_sizes():
        m = None  # Replace with your code to build the model
        target = maybe_substitute_thread(obtain_target())
        banks = find_register_banks(target.path)
        for bank in banks.values():
            path = bank.path
            for reg_name, bytes in REG_VALS.items():
                regs = m.find_all(TargetRegister, path, lambda x: x.apply_indices(reg_name), False).values()
                for reg in regs:
                    assert reg.bit_length() // 8 == len(bytes)

    @staticmethod
    def test_register_bank_is_where_expected():
        m = None  # Replace with your code to build the model
        target = maybe_substitute_thread(obtain_target())
        expected_register_bank_path = get_expected_register_bank_path(target.path)
        assume_not_null(expected_register_bank_path)
        banks = find_register_banks(target.path)
        for bank in banks.values():
            path = bank.path
            assert all(x in path for x in expected_register_bank_path)

    @staticmethod
    def test_read_registers():
        m = None  # Replace with your code to build the model
        target = maybe_substitute_thread(obtain_target())
        c = Objects.requireNonNull(m.find_with_index(TargetRegisterContainer, "0", target.path))
        banks = m.find_all(TargetRegisterBank, c.path, True).values()
        exp = REG_VALS.copy()
        read = {}
        for bank in banks:
            for reg_name, bytes in exp.items():
                regs = m.find_all(TargetRegister, bank.path, lambda x: x.apply_indices(reg_name), False).values()
                for reg in regs:
                    bytes_read = wait_on(bank.read_register(reg))
                    read[reg_name] = bytes_read
                    expect_register_object_value(bank, reg_name, bytes_read)
                    assert len(bytes) == len(bytes_read)

        assert set(exp.keys()) == set(read.keys())

    @staticmethod
    def test_write_registers():
        m = None  # Replace with your code to build the model
        target = maybe_substitute_thread(obtain_target())
        c = Objects.requireNonNull(m.find_with_index(TargetRegisterContainer, "0", target.path))
        banks = m.find_all(TargetRegisterBank, c.path, True).values()
        write = REG_VALS.copy()
        read = {}
        for bank in banks:
            for reg_name, bytes in write.items():
                regs = m.find_all(TargetRegister, bank.path, lambda x: x.apply_indices(reg_name), False).values()
                for reg in regs:
                    wait_on(bank.write_register(reg, bytes))
                    bytes_read = wait_on(bank.read_register(reg))
                    read[reg_name] = bytes_read
                    expect_register_object_value(bank, reg_name, bytes_read)
                    assert_array_equal(bytes, bytes_read)

        assert set(write.keys()) == set(read.keys())
