Here's a translation of your Java code into equivalent Python:

```Python
import datetime

class MergeProgramGenerator_Mips:
    def __init__(self, consumer):
        self.consumer = consumer
        self.last_generated_universal_id = None

    def generate_program(self, program_name):
        if program_name == "r4000":
            return self.build_r4000_program()
        else:
            raise Exception("Add new builder for program: {}".format(program_name))

    def build_r4000_program(self):
        from ghidra.program.model.listing import Program
        from ghidra.util.exception import AssertException

        builder = ProgramBuilder("r4000", "MIPS", self.consumer)
        builder.create_memory("label", "08000", 0x1000)
        builder.set_bytes(b"\x08\x8c\x0c\x10\xd0\x2b\x24\x04\x00\x33\x0c\x10\x7e\xa4\x24\x16\x00\x30\xaf\xa2\x00\x44\x40\x04\x78\x00\x00\x00\x00", True)
        builder.set_bytes(b"\x80\xb0\x24\x03\x00\x27\x14\x43\x00\x0a\x30\x82\x00\xff\x2c\x42\x00\x21\x14\x40\x00\x07", True)
        program = Program()
        program.date_created = datetime.datetime(100, 1, 1)  # arbitrary date
        AbstractGenericTest.set_instance_field("recordChanges", program, True)

        universal_id = UniversalIdGenerator.next_id()

        if self.last_generated_universal_id is not None:
            if self.last_generated_universal_id != universal_id:
                raise AssertException("Expected Test UniversalID has changed. This is probably due to an new static usage of the UniversalIDGenerator.")

        return program

class ProgramBuilder:
    def __init__(self, name, architecture, consumer):
        pass  # implementation left out for brevity

class AbstractGenericTest:
    @staticmethod
    def set_instance_field(field_name, instance, value):
        pass  # implementation left out for brevity

class UniversalIdGenerator:
    @staticmethod
    def next_id():
        return None  # implementation left out for brevity
```

Please note that I've omitted the implementations of `ProgramBuilder`, `AbstractGenericTest` and `UniversalIdGenerator` as they were not provided in your original Java code.