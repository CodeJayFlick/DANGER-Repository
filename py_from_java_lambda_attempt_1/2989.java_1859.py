Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script as GAS
from ghidra_program_model_listing import Function
from ghidra_program_util import CyclomaticComplexity

class ComputeCyclomaticComplexity:
    def run(self):
        if not hasattr(gas, 'currentProgram'):
            print("no current program")
            return
        
        function = gas.currentProgram.getFunctionContaining(gas.currentAddress)
        
        if function is None:
            print(f"no function containing current address {gas.currentAddress}")
            return
        
        cyclomatic_complexity = CyclomaticComplexity()
        print(f"complexity: {cyclomatic_complexity.calculateCyclomaticComplexity(function, gas.monitor)}")

# Initialize the script
gas = GAS.GhidraScript()

# Run the script
script = ComputeCyclomaticComplexity()
try:
    script.run()
except Exception as e:
    print("Error:", str(e))
```

Please note that this code is not a direct translation of the Java code, but rather an equivalent Python implementation. The `ghidra_app_script`, `ghidra_program_model_listing` and `ghidra_program_util` modules are used to interact with Ghidra's API in Python.