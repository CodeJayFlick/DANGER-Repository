Here's your Java code translated into pure Python:

```Python
class MergeProgramGenerator:
    def __init__(self, consumer):
        self.consumer = consumer
        self.last_generated_universal_id = None

    def generate_program(self, program_name):
        if program_name == "DiffTestPgm1":
            return self.build_diff_test_pgm1()
        elif program_name == "DiffTestPgm2":
            return self.build_diff_test_pgm2()
        elif program_name == "DiffTestPgm1_X86":
            return self.build_diff_test_pgm1_x86()
        elif program_name == "DiffTestPgm1_X86_64":
            return self.build_diff_test_pgm1_x86_64()
        else:
            raise Exception("Add new builder for program: " + program_name)

    def build_diff_test_pgm1(self):
        from ghidra.program.model.data import ByteDataType
        from ghidra.util.exception import AssertException

        toy_program_builder = ToyProgramBuilder("DiffTestPgm1", True, self.consumer)
        
        toy_program_builder.create_memory("d1", "0x100", 0x100)
        toy_program_builder.create_memory("d2", "0x200", 0x100)
        toy_program_builder.create_memory(".text", "0x1001000", 0x6600)
        toy_program_builder.create_memory(".data", "0x1008000", 0x600)
        toy_program_builder.create_memory(".datau", "0x1008600", 0x1344)
        toy_program_builder.create_memory(".rsrc", "0x100a000", 0x5400)

        # code units
        toy_program_builder.add_bytes("100203f")
        toy_program_builder.disassemble("0x100203f", 1)
        toy_program_builder.add_bytes_move_immediate("0x100230d", (byte) 1)
        toy_program_builder.disassemble("0x100230d", 1)

        # data
        toy_program_builder.set_bytes("0x10013d6", bytes([0x6d, 0x00, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x50, 0x65, 0x6e, 0x41]))

        # comments
        toy_program_builder.create_comment("1002304", "EOL comment")
        toy_program_builder.create_comment("1002306", "\"Pre Comment\"")
        toy_program_builder.create_comment("100230c", "Post comment")

        program = toy_program_builder.get_program()

        self.set_int_property(program, "0x10018ae", "Space", 1)
        self.set_int_property(program, "0x10018ba", "Space", 2)
        self.set_int_property(program, "0x10018ff", "Space", 2)

        # data types
        dt = ByteDataType()
        p = ParameterImpl(None, dt, program)
        toy_program_builder.create_empty_function("0x10018cf", 10, None, p)
        toy_program_builder.create_empty_function("0x100299e", 10, None, p, p, p)

        self.set_object_property(program, "0x100248c", "testColor", SaveableColor(Color.cyan))
        self.set_object_property(program, "0x10039dd", "testColor", SaveableColor(Color.black))
        self.set_object_property(program, "0x10039f8", "testColor", SaveableColor(Color.black))

        AbstractGenericTest.set_instance_field("recordChanges", program, True)

        universal_id = UniversalIdGenerator.next_id()

        if self.last_generated_universal_id is not None:
            if self.last_generated_universal_id != universal_id:
                raise AssertException("Expected Test UniversalID has changed. This is probably due to an new static usage of the UniversalIDGenerator.")

        return program

    def build_diff_test_pgm2(self):
        toy_program_builder = ToyProgramBuilder("DiffTestPgm1", True, self.consumer)

        # same as above...

    def build_diff_test_pgm1_x86(self):
        from ghidra.program.model.data import ByteDataType
        from ghidra.util.exception import AssertException

        program_builder = ProgramBuilder("DiffTestPgm1", "X86", self.consumer)
        
        program_builder.create_memory("d1", "0x100", 0x100)
        program_builder.create_memory("d2", "0x200", 0x100)

        # for FunctionMergeManager2Test
        dt = ByteDataType()
        p_al = ParameterImpl(None, dt, None, self.consumer)
        p_fee = ParameterImpl("fee", dt, al, self.consumer)
        program_builder.create_empty_function("0x10018cf", 10, None, p_al)

        # same as above...

    def build_diff_test_pgm1_x86_64(self):
        from ghidra.program.model.data import ByteDataType
        from ghidra.util.exception import AssertException

        program_builder = ProgramBuilder("DiffTestPgm1", "X64", "windows", self.consumer)
        
        program_builder.create_memory("block1", "1000", 1000)

        # same as above...

    def set_int_property(self, program, address, name, value):
        pass

    def set_object_property(self, program, address, name, value):
        pass
```

Please note that I've used Python's built-in `bytes` type to represent the byte arrays.