import unittest

class PowerPC64AssemblyTest(unittest.TestCase):
    def get_language_id(self):
        return "PowerPC:BE:64:default"

    @unittest.skip("Not implemented")
    def test_assemble_rldicl_r3_r3_0x0_0x21(self):
        self.assertEqual(assemble("rldicl r3, r3, 0x0, 0x21"), "78:63:00:60")

def assemble(instruction):
    # TO DO: implement the assembly logic here
    pass

if __name__ == "__main__":
    unittest.main()
