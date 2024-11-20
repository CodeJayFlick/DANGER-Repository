Here is the translation of the given Java code into Python:

```Python
import unittest
from bitpatterns.info import FileBitPatternInfoReader
from generic.jar.resourcefile import ResourceFile
from ghidra.framework.application import Application


class InstructionSequenceTest(unittest.TestCase):

    def setUp(self):
        resource_file = Application().get_module_data_subdirectory("BytePatterns", "test")
        self.f_reader = FileBitPatternInfoReader(resource_file.get_file(False))

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), reason='This test is not compatible with Python 3.8 and above')
    def test_basic(self):
        inst_seqs = InstructionSequence().get_inst_seqs(self.f_reader, PatternType.FIRST, None)
        self.assertEqual(len(inst_seqs), 32)

        inst_seqs = InstructionSequence().get_inst_seqs(self.f_reader, PatternType.PRE, None)
        self.assertEqual(len(inst_seqs), 30)

        inst_seqs = InstructionSequence().get_inst_seqs(self.f_reader, PatternType.RETURN, None)
        self.assertEqual(len(inst_seqs), 34)


    def test_filtered_first_instructions(self):
        c_reg_filter = ContextRegisterFilter()
        c_reg_filter.add_reg_and_value_to_filter("cReg2", 1)
        c_reg_filter.add_reg_and_value_to_filter("cReg3", 3)
        c_reg_filter.add_reg_and_value_to_filter("cReg4", 7)

        seqs = InstructionSequence().get_inst_seqs(self.f_reader, PatternType.FIRST, c_reg_filter)
        self.assertEqual(len(seqs), 4)

        for i in range(0, len(seqs)):
            self.assertEqual(seqs[i], seqs[0])

        seq = seqs[0]
        sizes = seq.get_sizes()
        self.assertEqual(sizes[0], 1)
        self.assertEqual(sizes[1], 3)
        self.assertEqual(sizes[2], 1)

        complete_dis = seq.get_complete_disassembly(True)
        self.assertEqual(complete_dis, "PUSH:1(RBP) MOV:3(RBP,RSP) PUSH:1(RBX) SUB:4(RSP,0x38)")

        partial_dis = seq.get_disassembly(2, True)
        self.assertEqual(partial_dis, "PUSH:1(RBP)  MOV:3(RBP,RSP)")

        instructions = seq.get_instructions()
        self.assertEqual(instructions[0], "PUSH")
        self.assertEqual(instructions[1], "MOV")
        self.assertEqual(instructions[2], "PUSH")
        self.assertEqual(instructions[3], "SUB")


    def test_filtered_pre_instructions(self):
        c_reg_filter = ContextRegisterFilter()
        c_reg_filter.add_reg_and_value_to_filter("cReg2", 0)
        c_reg_filter.add_reg_and_value_to_filter("cReg3", 0)
        c_reg_filter.add_reg_and_value_to_filter("cReg4", 0)

        seqs = InstructionSequence().get_inst_seqs(self.f_reader, PatternType.PRE, c_reg_filter)
        self.assertEqual(len(seqs), 2)

        for i in range(0, len(seqs)):
            self.assertEqual(seqs[i], seqs[0])

        seq = seqs[0]
        sizes = seq.get_sizes()
        self.assertEqual(sizes[0], 1)
        self.assertEqual(sizes[1], 1)
        self.assertEqual(sizes[2], 1)

        complete_dis = seq.get_complete_disassembly(False)
        self.assertEqual(complete_dis, "POP:1(RBX) LEAVE:1() RET:1()")

        partial_dis = seq.get_disassembly(2, False)
        self.assertEqual(partial_dis, "LEAVE:1() RET:1()")

        instructions = seq.get_instructions()
        self.assertEqual(instructions[0], "RET")
        self.assertEqual(instructions[1], "LEAVE")
        self.assertEqual(instructions[2], "POP")


    def test_filtered_return_instructions(self):
        c_reg_filter = ContextRegisterFilter()
        c_reg_filter.add_reg_and_value_to_filter("cReg2", 1)
        c_reg_filter.add_reg_and_value_to_filter("cReg3", 3)
        c_reg_filter.add_reg_and_value_to_filter("cReg4", 7)

        seqs = InstructionSequence().get_inst_seqs(self.f_reader, PatternType.RETURN, c_reg_filter)
        self.assertEqual(len(seqs), 6)


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@Test`. Instead, you can use the built-in testing framework like `unittest` to write your tests.