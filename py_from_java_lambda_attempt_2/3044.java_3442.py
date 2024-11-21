Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script as script
from ghidra.app.util import importer_message_log as MessageLog
from ghidra.program.util import elf_external_symbol_resolver as ELFExternalSymbolResolver
from ghidra.util.msg import Msg

class FixupELFExternalSymbolsScript(script.GhidraScript):
    def run(self) -> None:
        if not script.elf_loader.ElfLoader.NAME == self.current_program.get_executable_format():
            Msg.show_error(self, None, "FixupELFExternalSymbols", f"Current program is not an ELF program! ({self.current_program.get_executable_format()})")
            return
        msg_log = MessageLog()
        elf_external_symbol_resolver.fix_unresolved_external_symbols(self.current_program, False, msg_log, self.monitor)
        Msg.info(self, str(msg_log))
```

Please note that this Python code is a direct translation of the given Java code. It may not work as expected if you are trying to run it in an environment where `ghidra_app_script`, `MessageLog`, and other modules are not available or properly configured.