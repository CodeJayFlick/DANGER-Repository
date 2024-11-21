Here is the translation of the given Java code into Python:

```Python
import ghidra.app.script.GhidraScript
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.NumericUtilities import convert_bytes_to_string

class LanguagesAPIDemoScript(GhidraScript):
    def run(self):
        # The API is accessed using a callback, so instantiate the class to receive that callback.
        visitor = DumpPcodeOps()
        
        # Perform the iteration with the given callback visitor.
        result = SleighLanguages.traverse_all_pcode_ops(current_program.get_language(), visitor)
        print("Result:", result)

class DumpPcodeOps:
    def visit(self, subtable, pattern, constructor, op):
        if self.monitor.is_cancelled():
            return TERMINATE
        
        # Consider only root constructors
        if not "instruction".equals(subtable.name()):
            return CONTINUE
        
        # Check any opcode is a return, and do something interesting if it does.
        if op is not None and op.get_opcode() == PcodeOp.RETURN:
            whole = pattern.get_whole_instruction_bytes()
            pat = convert_bytes_to_string(whole)
            print(subtable.name(), "(", pat, ",", constructor, "):", op)
        
        return CONTINUE
```

Please note that Python does not support direct translation of Java code. The above code is a manual translation and may require some adjustments to work correctly in your specific environment.