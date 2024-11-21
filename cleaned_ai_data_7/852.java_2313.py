class AbstractModelForDbgengX64RegistersTest:
    REG_VALS = {
        "rax": bytes.fromhex("0123456789abcdef"),
        # "ymm0": bytes.fromhex("0123456789abcdeffedcba9876543210"),  # TODO: Why 16 bytes instead of 32? 
        # "ymm0": bytes.fromhex("0011223344556677889922aabbccddeeff") * 2,  # uncomment this line to test with 32 bytes
    }

    def get_test(self):
        return self

    def get_expected_register_bank_path(self, thread_path: list) -> list:
        from ghidra.util.path import PathUtils
        return PathUtils.extend(thread_path, ["Registers"])

    def get_register_writes(self) -> dict:
        return self.REG_VALS.copy()

    def get_launch_specimen(self):
        # Note that this is a placeholder for the actual implementation.
        # In Python, you would typically use an object-oriented approach
        # to represent different types of launch specimens. For simplicity,
        # we'll just hardcode "WindowsSpecimen.PRINT" here:
        return {"type": "PRINT", "platform": "WINDOWS"}
