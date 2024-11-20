Here is the equivalent Python code:

```Python
import unittest
from ghidra_program import ProgramBuilder, Program, PseudoDisassembler


class TestPseudoDisassembler(unittest.TestCase):

    def setUp(self):
        self.program_builder = ProgramBuilder("Test", "ARM")
        self.program = self.program_builder.get_program()
        tx_id = self.program.start_transaction("Add Memory")  # leave open until tearDown
        memory_text = self.program_builder.create_memory(".text", "0x00", 64).set_execute(True)
        memory_unint = self.program_builder.create_uninitialized_memory(".unint", "0x40", 64).set_execute(True)
        memory_dat = self.program_builder.create_uninitialized_memory(".dat", "0x80", 64)  # no-execute
        memory_text2 = self.program_builder.create_memory(".text2", "0x3e0", 0x800).set_execute(True)

        self.disassembler = PseudoDisassembler(self.program)
        return

    def tearDown(self):
        if self.program is not None:
            self.program.end_transaction(tx_id, True)  # close transaction
        if self.program_builder is not None:
            self.program_builder.dispose()  # dispose program builder


class TestPseudoDisassembly(unittest.TestCase):

    def test_to_string_arm_separator(self):
        self.program_builder.set_bytes("0", b"\x08\xf8\x00\x00\x40\x00")  # strb.w r0,[r8,r0,0x0]
        self.program_builder.set_register_value("TMode", "0", "1", 1)
        instr = self.disassembler.disassemble(self.program.get_address_factory().get_address("0"))

        str_instr = str(instr)  # convert PseudoInstruction to string
        self.assertEqual(str_instr, "strb.w r0,[r8,r0,lsl #0x0]")  # test expected output

        self.program_builder.set_bytes("0", b"\x00\xf0\x20\x03")  # nopeq
        self.program_builder.set_register_value("TMode", "0", "1", 0)
        instr = self.disassembler.disassemble(self.program.get_address_factory().get_address("0"))

        str_instr = str(instr)  # convert PseudoInstruction to string
        self.assertEqual(str_instr, "nopeq")  # test expected output


if __name__ == "__main__":
    unittest.main()
```

This Python code is equivalent to the provided Java code. It uses the `unittest` module for unit testing and creates a `ProgramBuilder`, `Program`, and `PseudoDisassembler`. The tests are similar to those in the original Java code, but with some minor differences due to language-specific features (e.g., no need for an explicit constructor).