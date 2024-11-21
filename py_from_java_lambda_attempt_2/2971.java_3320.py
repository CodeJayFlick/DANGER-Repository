Here is the translation of the given Java code into Python:

```Python
import ghidra_app_plugin_assembler
from ghidra_program_model_listing import Instruction
from ghidra_current_program import currentProgram

class AssembleCheckDevScript:
    def run(self):
        print("Constructing Assember")
        checker = AllMatchByTextSelector()
        asm = assemblers.getAssembler(currentProgram, checker)
        ins = currentProgram.getListing().getInstructionAt(currentAddress)
        
        if ins is not None:
            print("Assembling")
            checker.setExpected(ins)
            print(f"Assembling {ins.getAddress()}: {ins}")
            
            try:
                asm.assemble(ins.getAddress(), str(ins))
            except Exception as e:
                pass  # Do nothing.

# Usage
script = AssembleCheckDevScript()
script.run()

```

Please note that this translation is not a direct conversion from Java to Python. The code structure and syntax are different between the two languages, so some modifications were necessary for it to be valid Python code.