Here is the translation of the given Java code into Python:

```Python
import hashlib
from typing import Tuple, List

class ExactInstructionsFunctionHasher:
    INSTANCE = None

    def __init__(self):
        self.digest = FNV1a64MessageDigest()

    @staticmethod
    def get_instance():
        if not isinstance(ExactInstructionsFunctionHasher.INSTANCE, ExactInstructionsFunctionHasher):
            ExactInstructionsFunctionHasher.INSTANCE = ExactInstructionsFunctionHasher()
        return ExactInstructionsFunctionHasher.INSTANCE

    def common_bit_count(self, func_a: 'ghidra.program.model.lang.Function', 
                          func_b: 'ghidra.program.model.lang.Function', monitor) -> int:
        count = 0
        a_code_units_pair = self.get_all_code_units(monitor, func_a.get_program(), func_a.get_body())
        b_code_units_pair = self.get_all_code_units(monitor, func_b.get_program(), func_b.get_body())

        if len(a_code_units_pair[1]) != len(b_code_units_pair[1]):
            return 0

        for ii in range(len(a_code_units_pair[1])):
            a_unit = a_code_units_pair[1][ii]
            b_unit = b_code_units_pair[1][ii]

            try:
                a_bytes = a_unit.get_bytes()
                b_bytes = b_unit.get_bytes()

                if len(a_bytes) == len(b_bytes):
                    for jj in range(len(a_bytes)):
                        count += bin((0xff & ~(a_bytes[jj] ^ b_bytes[jj]))).count('1')
            except MemoryAccessException:
                pass

        return count

    def hash(self, monitor: 'ghidra.util.task.TaskMonitor', units: List['ghidra.program.model.mem.CodeUnit'], byte_count) -> int:
        buffer = bytearray(byte_count)
        offset = 0
        for code_unit in units:
            if monitor.is_cancelled():
                return -1

            try:
                code_unit.get_bytes_in_code_unit(buffer, offset)
                self.apply_mask(buffer, offset, code_unit)
            except MemoryAccessException as e:
                print(f"Could not get code unit bytes at {code_unit.get_address()}")

            offset += code_unit.get_length()

        if offset != byte_count:
            raise ValueError("did NOT use all the codeUnit buffer bytes")

        self.digest.reset()
        self.digest.update(buffer, monitor)
        return int.from_bytes(self.digest.digest(), 'big')

    @staticmethod
    def apply_mask(buffer: bytearray, offset: int, code_unit) -> None:
        if not isinstance(code_unit, Instruction):
            return

        instruction = code_unit
        mask = instruction.get_prototype().get_instruction_mask()
        if mask is None:
            return

        try:
            mask.apply_mask(buffer, offset, buffer, offset)
        except IncompatibleMaskException as e:
            raise Exception(e)

    def get_all_code_units(self, monitor: 'ghidra.util.task.TaskMonitor', program: 'ghidra.program.model.Program', body) -> Tuple[int, List['ghidra.program.model.mem.CodeUnit']]:
        # implement this method
        pass

class FNV1a64MessageDigest:
    def reset(self):
        pass

    def update(self, buffer: bytearray, monitor) -> None:
        pass

    def digest(self) -> bytes:
        return b''

class Instruction:
    def get_prototype(self) -> 'ghidra.program.model.lang.InstructionPrototype':
        # implement this method
        pass

# Usage example:

hasher = ExactInstructionsFunctionHasher.get_instance()
func_a = ...  # your function a here
func_b = ...  # your function b here
monitor = ...  # your task monitor here
print(hasher.common_bit_count(func_a, func_b, monitor))
```

Please note that this is not the actual implementation of `FNV1a64MessageDigest` and `Instruction`, as they are specific to GHIDRA. You would need to implement these classes according to their original definitions in Java or find equivalent Python implementations for them.

Also, some methods like `get_all_code_units` are left unimplemented as it's not clear how you want to get the code units from your functions and program.