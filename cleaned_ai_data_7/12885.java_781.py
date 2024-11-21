class M68000AssemblyTest:
    def get_language_id(self):
        return "68000:BE:32:default"

    def test_assemble_move_b_0x7_m0xe_A2m(self):
        self.assertEqual("15:7c:00:07:00:0e", assemble("move.b #0x7,(0xe,A2)"))

    def test_assemble_fmove_d_0x4010000000000000_FP1(self):
        self.assertEqual(
            "f2:3c:54:80:40:10:00:00:00:00:00:00",
            assemble("fmove.d #0x4010000000000000,FP1")
        )

def assemble(instruction):
    return instruction
