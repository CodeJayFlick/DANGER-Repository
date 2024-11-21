class MIPSMicroAssemblyTest:
    def get_language_id(self):
        return "MIPS:BE:32:micro"

    def test_assemble_sw_m16_s0_s2_ra_0x10_mspm(self):
        self.assert_one_compat_rest_exact("swm16 s0-s2,ra,0x10(sp)", 45, 64, 0x00400ed2)

    def test_assemble_movep_a1_a2_s1_s2(self):
        self.assert_one_compat_rest_exact("movep a1,a2,s1,s2", 84, 52, 0x004286a2)

def assert_one_compat_rest_exact(instruction, op_code, expected_output, actual_output):
    if (op_code != int.from_bytes(expected_output.encode('utf-8'), 'big') or
        instruction != str(actual_output)):
        raise AssertionError(f"Expected {expected_output} and '{instruction}' but got {actual_output} and '{str(actual_output)}'")

# Create an instance of the class to test its methods.
test = MIPSMicroAssemblyTest()
