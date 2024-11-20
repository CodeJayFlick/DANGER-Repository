import unittest
from ghidra_program import ProgramBuilder, TestEnv, Address


class ProgramUtilitiesTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        self.builder = ProgramBuilder("notepad", "TOY")
        self.builder.create_memory("test1", hex(0x1001000), 0x2000)

    def tearDown(self):
        self.env.dispose()
        self.builder.dispose()

    @unittest.skip
    def test_parse_address(self):

        program = self.builder.get_program()
        addr_stack_54 = Address.parse_address(program, "Stack[54]")
        self.assertEqual(addr_stack_54.address_space, program.get_address_factory().get_stack_space())
        self.assertEqual(54, addr_stack_54.offset)

        addr_stack_0x54 = Address.parse_address(program, "Stack[0x54]")
        self.assertEqual(addr_stack_0x54.address_space, program.get_address_factory().get_stack_space())
        self.assertEqual(0x54, addr_stack_0x54.offset)

        addr_stack_minus_54 = Address.parse_address(program, "Stack[-54]")
        self.assertEqual(addr_stack_minus_54.address_space, program.get_address_factory().get_stack_space())
        self.assertEqual(-54, addr_stack_minus_54.offset)

        addr_stack_minus_0x54 = Address.parse_address(program, "Stack[-0x54]")
        self.assertEqual(addr_stack_minus_0x54.address_space, program.get_address_factory().get_stack_space())
        self.assertEqual(-0x54, addr_stack_minus_0x54.offset)


if __name__ == '__main__':
    unittest.main()
