Here is the equivalent Python code:

```Python
class GnuDisassembledInstruction:
    def __init__(self, instruction_line: str, bytes_in_instruction: int,
                 is_valid: bool, branch_delay_instructions: int, data_size: int, dis_insn_typeordinal: int):
        self.instruction = instruction_line.strip()
        self.bytes_in_instruction = bytes_in_instruction
        self.is_valid = is_valid
        self.branch_delay_instructions = branch_delay_instructions
        self.data_size = data_size
        self.instruction_type = GnuDisassembledInstruction.DIS_INSN_TYPE(dis_insn_typeordinal)

    def get_number_of_bytes_in_instruction(self):
        return self.bytes_in_instruction

    def get_instruction_type(self) -> 'DIS_INSN_TYPE':
        if self.is_valid:
            return self.instruction_type
        else:
            return None

    def get_branch_delay_instructions(self) -> int:
        return self.branch_delay_instructions if self.is_valid else None

    def get_data_size(self) -> int:
        return self.data_size if self.is_valid else None

    def get_instruction(self):
        return self.instruction

    def __str__(self):
        return self.instruction


class DIS_INSN_TYPE(enum.Enum):
    dis_noninsn = 1
    dis_nonbranch = 2
    dis_branch = 3
    dis_condbranch = 4
    dis_jsr = 5
    dis_condjsr = 6
    dis_dref = 7
    dis_dref2 = 8

```

Note: The `enum` class is not built-in in Python, you would need to use the `python-enum34` package for this.