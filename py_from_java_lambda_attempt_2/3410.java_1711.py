Here is the translation of the Java code to Python:
```python
import re

class ElfScalarOperandAnalyzer:
    NAME = "ELF Scalar Operand References"
    DESCRIPTION = (
        "For ELF shared objects (.so) files that are based at zero,"
        + " offsets relative to the .got offsets appear to be valid addresses"
        + " and therefore invalid memory references get created by the analyzer."
        + " This analyzer will remove those bad references."
    )

    def __init__(self):
        super().__init__(self.NAME, self.DESCRIPTION)

    @property
    def can_analyze(self, program: 'Program') -> bool:
        return is_elf(program)

    @property
    def default_enablement(self, program: 'Program') -> bool:
        if not is_elf(program):
            return False
        return self.default_enablement2(program)

    def add_reference(
        self,
        program: 'Program',
        instr: 'Instruction',
        op_index: int,
        space: str,
        scalar: 'Scalar'
    ) -> bool:
        if program.executable_format == "ELF":
            mnemonic = instr.mnemonic_string.lower()
            if mnemonic == "add":
                try:
                    got_addr = instr.min_address + scalar.unsigned_value
                    block = program.memory.block(got_addr)
                    if block is not None and ".got" in block.name:
                        return False
                except AddressOutOfBoundsException:
                    pass
            elif mnemonic == "push":
                block = program.memory.block(instr.min_address)
                if block is not None and ".plt" in block.name:
                    return False
        return super().add_reference(program, instr, op_index, space, scalar)

def is_elf(program: 'Program') -> bool:
    # implement this function to check if the program is an ELF file
    pass

class Program:
    def __init__(self):
        self.executable_format = None  # set by some other code

class Instruction:
    def __init__(self):
        self.mnemonic_string = None  # set by some other code
        self.min_address = None  # set by some other code

class Scalar:
    def __init__(self):
        self.unsigned_value = None  # set by some other code

# implement the is_elf function and the Program, Instruction, and Scalar classes to match your specific use case
```
Note that I had to make some assumptions about the Python types (`Program`, `Instruction`, `Scalar`) since they were not defined in the original Java code. You will need to implement these classes or modify them to fit your specific use case.

Also, I did not translate the Apache License header as it is a separate file and does not contain any executable code.