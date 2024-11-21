Here is the translation of the Java code into Python:

```Python
class InstructionBlock:
    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.is_start_of_flow = False
        self.max_address = None
        self.flow_from = None
        self.last_instruction_address = None
        self.fallthrough_address = None
        self.instruction_map = {}
        self.flow_addresses = []
        self.block_flows = []

    def set_start_of_flow(self, is_start):
        self.is_start_of_flow = is_start

    def is_flow_start(self):
        return self.is_start_of_flow

    @property
    def start_address(self):
        return self.start_addr

    @property
    def max_address(self):
        if not self.max_address:
            return self.start_addr
        else:
            return self.max_address

    def get_instruction_at(self, address):
        return self.instruction_map.get(address)

    def find_first_intersecting_instruction(self, min, max):
        intersect_instr = None
        for instr in self.instruction_map.values():
            if instr.min_address > max:
                continue
            if instr.max_address < min:
                continue
            if intersect_instr and intersect_instr.min_address < instr.min_address:
                continue
            intersect_instr = instr
        return intersect_instr

    def __str__(self):
        return f"[ {self.start_addr} {"-" + self.max_address if self.max_address else ": <empty>"} ]"

    def add_instruction(self, instruction):
        min_addr = instruction.min_address
        if not self.max_address:
            if min_addr != self.start_addr:
                raise ValueError("First instruction to block had address " + str(min_addr) +
                                  ", expected address " + str(self.start_addr))
        else:
            if not self.max_address.is_successor(min_addr):
                raise ValueError("Newly added instruction at address " + str(min_addr) +
                                 " is not the immediate successor to address " + str(self.max_address))

        self.instruction_map[min_addr] = instruction
        if not instruction.is_in_delay_slot:
            self.last_instruction_address = min_addr
        self.max_address = instruction.max_address

    def add_block_flow(self, block_flow):
        if not self.block_flows:
            self.block_flows = []
        self.block_flows.append(block_flow)

    def add_branch_flow(self, destination_address):
        self.flow_addresses.append(destination_address)

    @property
    def fallthrough_address(self):
        return self.fallthrough_address

    @fallthrough_address.setter
    def fallthrough_address(self, address):
        self.fallthrough_address = address

    def get_branch_flows(self):
        return self.flow_addresses

    def get_block_flows(self):
        return self.block_flows

    def set_instruction_error(self, type, intended_instruction_address,
                               conflict_address, flow_from_address, message):
        if type == InstructionErrorType.PARSE:
            raise ValueError("use set_parse_conflict for PARSE conflicts")
        self.instruction_error = InstructionError(self, type, intended_instruction_address,
                                                   conflict_address, flow_from_address, message)

    def set_instruction_memory_error(self, instr_addr, flow_from_addr, error_msg):
        self.set_instruction_error(InstructionErrorType.MEMORY, instr_addr, instr_addr, flow_from_addr, error_msg)

    def set_inconsistent_prototype_conflict(self, instr_addr, flow_from_addr):
        self.set_instruction_error(InstructionErrorType.INSTRUCTION_CONFLICT, instr_addr,
                                   instr_addr, flow_from_addr, "Multiple flows produced inconsistent instruction prototype at " + str(instr_addr) +
                                                                                                " - possibly due to inconsistent context")

    def set_code_unit_conflict(self, code_unit_addr, new_instr_addr, flow_from_addr, is_instruction, is_offcut):
        error_type = InstructionErrorType.INSTRUCTION_CONFLICT if is_instruction else InstructionErrorType.DATA_CONFLICT
        self.set_instruction_error(error_type, new_instr_addr, code_unit_addr, flow_from_addr,
                                   "Failed to disassemble at " + str(new_instr_addr) +
                                                                                                " due to conflicting " + ("instruction" if is_instruction else "data") + " at " + str(code_unit_addr))

    def set_parse_conflict(self, conflict_address, context_value, flow_from_address, message):
        self.instruction_error = InstructionError(self, context_value, conflict_address,
                                                   flow_from_address, message)

    def clear_conflict(self):
        self.instruction_error = None

    @property
    def instruction_error(self):
        return self._instruction_error

    @instruction_error.setter
    def instruction_error(self, error):
        if not isinstance(error, InstructionError):
            raise ValueError("Instruction Error must be an instance of InstructionError")
        self._instruction_error = error

    def get_instruction_conflict(self):
        return self.instruction_error

    def __iter__(self):
        return iter(self.instruction_map.values())

    @property
    def last_instruction_address(self):
        return self.last_instruction_address

    def is_empty(self):
        return not bool(self.instruction_map)

    @property
    def instruction_count(self):
        return len(self.instruction_map)

    @instruction_count.setter
    def instructions_added_count(self, count):
        if count < 0:
            raise ValueError("Number of added instructions cannot be negative")
        self._instructions_added_count = count

    @property
    def flow_from_address(self):
        return self.flow_from

    @flow_from_address.setter
    def flow_from_address(self, address):
        self.flow_from = address

    def has_instruction_error(self):
        return bool(self.instruction_error)
```

Note: The `InstructionError` class is not provided in the original Java code. It seems to be a custom error type that represents an instruction-level conflict or error during disassembly. You would need to implement this class yourself, possibly by extending Python's built-in `Exception` class.

Also note that some methods have been modified slightly for compatibility with Python syntax and semantics.