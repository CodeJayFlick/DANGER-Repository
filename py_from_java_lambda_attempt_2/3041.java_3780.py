Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script as GAS
from ghidra_program_model_address import Address
from ghidra_program_model_listing_codeunit import CodeUnit
from ghidra_program_model_listing_instruction import Instruction
from ghidra_pseudo_disassembler import PseudoDisassembler

class FindX86RelativeCallsScript:
    def run(self):
        addr = current_program.get_memory().get_min_address()
        pdis = PseudoDisassembler(current_program)

        exec_set = current_program.get_memory().get_execute_set()
        dis_set = set()

        while addr is not None:
            addr = self.find(addr, 0xe8)
            if addr is None:
                break

            if not exec_set or exec_set.issuperset({addr}):
                cu = current_program.get_listing().get_undefined_data_at(addr)
                if cu is not None:
                    instr = pdis.disassemble(addr)

                    target = instr[0].address
                    if current_program.get_memory().contains(target) and (not exec_set or exec_set.issuperset({target})):
                        # Create a function at the target address.
                        real_instr = current_program.get_listing().get_instruction_at(target)
                        if real_instr is None:
                            pdis.is_valid_subroutine(target, True)
                            disassemble(target)
                            dis_set.add(addr)

        GAS.show("X86 Relative Calls", dis_set)

# Usage
script = FindX86RelativeCallsScript()
script.run()
```

Please note that this Python code uses the `ghidra_app_script` module which is specific to Ghidra, a reverse engineering framework. This script should be run within the context of a Ghidra program analysis session.