class InVmModelForDbgmodelX64RegistersTest:
    REG_VALSX = {
        "rax": bytearray(b"0123456789abcdef"),
        "rdx": bytearray(b"fedcba9876543210")
    }

    def model_host(self):
        return InVmDbgmodelModelHost()

    def is_register_bank_also_container(self):
        return False

    def get_expected_register_bank_path(self, thread_path):
        from ghidra.util.path import extend
        return extend(thread_path, ["Registers", "User"])

    def get_register_writes(self):
        return self.REG_VALSX.copy()

    @staticmethod
    def test_registers_have_expected_sizes():
        pass  # This method is ignored in the original code

class InVmDbgmodelModelHost:
    pass
