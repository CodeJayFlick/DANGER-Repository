Here is the translation of the given Java code into Python:

```Python
import ghidra.app.command.disassemble.DisassembleCommand
from ghidra.program.model.address import AddressSet
from ghidra.util.Msg import Msg
from ghidra.app.script.GhidraScript import GhidraScript, currentProgram

class DoARMDisassemble(GhidraScript):
    def run(self) -> None:
        arm_processor = Processor.find_or_create("ARM")
        
        if not (current_program and 
                current_program.get_language().get_processor() == arm_processor):
            Msg.show_error(None, "Script Error", 
                           "Script only supports programs with ARM language")
            return

        tmode_reg = current_program.get_context_register("TMode")

        if tmode_reg:
            arm_mode = RegisterValue(tmode_reg, 0)

        address_set = AddressSet()
        
        if not (current_selection and len(current_selection)):
            address_set.add_range(current_address, current_address)
        else:
            address_set.update(current_selection)

        disassemble_command = DisassembleCommand(address_set, None, True)
        disassemble_command.set_initial_context(arm_mode)
        disassemble_command.apply_to(current_program, monitor)
```

Please note that Python does not support Java's `@Override` annotation. Also, the equivalent of Java's `throws Exception` is omitted in this translation as it depends on how you want to handle exceptions in your script.