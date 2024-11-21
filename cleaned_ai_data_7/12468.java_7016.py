class InstructionError:
    def __init__(self, block: 'InstructionBlock', error_type: str, instruction_address: int,
                 conflict_address: int = None, flow_from_address: int = None, message: str = '') -> None:
        self.block = block
        if error_type in ['DUPLICATE', 'INSTRUCTION_CONFLICT']:
            self.type = InstructionErrorType.DUPLICATE
        elif error_type == 'DATA_CONFLICT':
            self.type = InstructionErrorType.DATA_CONFLICT
        elif error_type == 'OFFCUT_INSTRUCTION':
            self.type = InstructionErrorType.OFFCUT_INSTRUCTION
        elif error_type == 'PARSE':
            self.type = InstructionErrorType.PARSE
            self.parse_context = None  # equivalent to RegisterValue in Java
        else:
            raise ValueError(f"Invalid instruction error type: {error_type}")
        if conflict_address is not None and flow_from_address is not None:
            self.conflict_address = conflict_address
            self.flow_from_address = flow_from_address
        self.message = message

    def get_instruction_block(self) -> 'InstructionBlock':
        return self.block

    def get_error_type(self) -> str:
        return self.type.name if isinstance(self.type, InstructionErrorType) else ''

    def is_instruction_conflict(self) -> bool:
        return self.get_error_type() in ['DUPLICATE', 'INSTRUCTION_CONFLICT']

    def is_offcut_error(self) -> bool:
        return self.get_error_type() == 'OFFCUT_INSTRUCTION'

    def get_instruction_address(self) -> int:
        return self(instruction_address)

    def get_conflict_address(self) -> int:
        if hasattr(self, 'conflict_address'):
            return self.conflict_address
        else:
            return None

    def get_parse_context_value(self) -> object:  # equivalent to RegisterValue in Java
        return self.parse_context

    def get_flow_from_address(self) -> int:
        if hasattr(self, 'flow_from_address'):
            return self.flow_from_address
        else:
            return None

    def get_message(self) -> str:
        return self.message


class InstructionErrorType:
    DUPLICATE = 1
    INSTRUCTION_CONFLICT = 2
    DATA_CONFLICT = 3
    OFFCUT_INSTRUCTION = 4
    PARSE = 5
    MEMORY = 6

    def __init__(self, is_conflict: bool) -> None:
        self.is_conflict = is_conflict


def dump_instruction_difference(new_inst: 'Instruction', existing_instr: 'Instruction') -> None:
    buf = f"Instruction conflict details at {new_inst.get_address()}\n"
    buf += "  New Instruction:\n"
    buf += get_instruction_details(new_inst)
    buf += "\n  Existing Instruction:\n"
    buf += get_instruction_details(existing_instr)
    print(buf)


def get_instruction_details(instr: 'Instruction') -> str:
    return f"{instr.__str__()}\n{get_formatted_context_register_value_breakout(instr)}"


# Helper function to format the context register value
def get_formatted_context_register_value_breakout(instr) -> str:
    # This is equivalent to InstructionUtils.getFormattedContextRegisterValueBreakout in Java
    pass


class RegisterValue:  # equivalent to RegisterValue in Java
    def __init__(self, value):
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value
