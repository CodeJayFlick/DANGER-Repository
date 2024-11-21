Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script as GhidraScript
from ghidra_program_model_address import Address
from ghidra_program_model_block_codeblock import CodeBlock
from ghidra_program_model_listing_instructioniterator import InstructionIterator
from ghidra_program_model_symbol_ref_type import RefType

class CreateFunctionAfterTerminals(GhidraScript):
    def __init__(self):
        self.numTried = 0
        self.numCreated = 0

    def run(self):
        inst_iter = currentProgram.getListing().getInstructions(True)
        while inst_iter.hasNext() and not monitor.isCancelled():
            instruction = inst_iter.next()
            if instruction.getFlowType() == RefType.TERMINATOR:
                func_addr = instruction.getMaxAddress().next()
                func = currentProgram.getFunctionManager().getFunctionContaining(func_addr)
                if func is None:
                    self.numTried += 1
                    func_begin_instr = currentProgram.getListing().getInstructionAt(func_addr)
                    if func_begin_instr is not None:
                        create_function_near(func_addr)

    def create_function_near(self, addr):
        partition_block_model = PartitionCodeSubModel(currentProgram)
        blocks = partition_block_model.getCodeBlocksContaining(addr, monitor)
        if len(blocks) != 1:
            print("*************************** Couldn't handle it at " + str(addr))
            return None
        address = blocks[0].getFirstStartAddress()
        func = create_function(address, None)
        if func is None:
            print("Tried to create Function At " + str(addr) + " unsuccessfully")
        else:
            print("Created Function At " + str(address))
            self.numCreated += 1
        return func

# Usage example:
script = CreateFunctionAfterTerminals()
script.run()
```

Please note that this translation is not a direct conversion from Java to Python. The original code seems to be part of the Ghidra software, and some parts might require additional setup or context specific to your environment.