Here is the equivalent Python code:

```Python
import ghidra

class DumpFunctionBitPatternInfoForCurrentFunctionScript:
    NUM_FIRST_BYTES = 10
    NUM_FIRST_INSTRUCTIONS = 4
    NUM_PRE_BYTES = 10
    NUM_PRE_INSTRUCTIONS = 4
    NUM_RETURN_BYTES = 12
    NUM_RETURN_INSTRUCTIONS = 4
    context_registers = None

    def run(self):
        params = ghidra.bitpatterns.info.DataGatheringParams()
        params.num_pre_bytes = self.NUM_PRE_BYTES
        params.num_first_bytes = self.NUM_FIRST_BYTES
        params.num_return_bytes = self.NUM_RETURN_BYTES
        params.num_pre_instructions = self.NUM_PRE_INSTRUCTIONS
        params.num_first_instructions = self.NUM_FIRST_INSTRUCTIONS
        params.num_return_instructions = self.NUM_RETURN_INSTRUCTIONS
        params.context_registers = self.context_registers

        func = current_program.get_function_manager().get_function_containing(current_address)
        if func is None:
            print("No function at currentAddress " + str(current_address))
            return
        f_start = ghidra.bitpatterns.info.FunctionBitPatternInfo(current_program, func, params)
        print(str(f_start))

# Usage: 
script = DumpFunctionBitPatternInfoForCurrentFunctionScript()
script.run()
```

Please note that this is a direct translation of the Java code to Python. The `ghidra` module in Python might be different from what you have used in your original Java code, and it's not guaranteed to work exactly as expected without further modifications or configuration.