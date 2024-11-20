class AARCH64BEAssemblyTest:
    def get_language_id(self):
        return "AARCH64:BE:64:v8A"

    def test_assemble_ldr_w0_mx1_w0_UXTW_0x2m(self):
        self.assert_one_compat_rest_exact("ldr w0,[x1, w0, UXTW #0x2]", 20, 58, 60, b'80')

    def test_assemble_ubfiz_w0_w0_0x3_0x5(self):
        self.assert_one_compat_rest_exact("ubfiz w0,w0,#0x3,#0x5", 0, 10, 1d, 53)

    # ... and so on for the rest of the test methods

    def assert_one_compat_rest_exact(self, assembly_code, *expected_bytes):
        print(f"Testing: {assembly_code}")
        expected_bytes = [int.from_bytes(bytearray([byte]), 'big') for byte in expected_bytes]
        actual_bytes = self.assemble(assembly_code)
        if actual_bytes != expected_bytes:
            raise AssertionError(f"{assembly_code} did not produce the expected bytes")

    def assemble(self, assembly_code):
        # This method should be implemented to actually perform the assembly
        pass

if __name__ == "__main__":
    test = AARCH64BEAssemblyTest()
    test.test_assemble_ldr_w0_mx1_w0_UXTW_0x2m()
    # ... and so on for the rest of the tests
