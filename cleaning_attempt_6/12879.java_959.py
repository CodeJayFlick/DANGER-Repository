class ARMAssemblyTest:
    THUMB = "80:00:00:00:00:00:00:00"
    T_CONDITION_ETT_EQ = "80:24:00:00:00:00:00:00"

    def get_language_id(self):
        return {"ARM", "BE", 32, 7}

    def test_assemble_bl_0x000230b8(self):
        self.assert_one_compat_rest_exact("bl 0x000230b8", "eb:00:6c:21", 0x0000802c)

    def test_assemble_and_r0_r0_n0xc40000(self):
        self.assert_one_compat_rest_exact(
            "and r0, r0, #0xc40000",
            "f4:00:00:44",
            ARMAssemblyTest.THUMB,
            0x00030464,
            "and r0, r0, #0xc40000"
        )

    def assert_one_compat_rest_exact(self, assembly_code, expected_output, thumb=None, value=0):
        if not thumb:
            print(f"Assembling: {assembly_code}")
            print(f"Expected output: {expected_output}")
            print(f"Value: 0x{value:x}")
