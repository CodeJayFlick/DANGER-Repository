Here is the translation of the given Java code into Python:

```Python
import ghidra.app.cmdformats.portableexecutablebinaryanalysiscommand as pe_command
from ghidra.app.script import GhidraScript


class PE_script(GhidraScript):
    def run(self, *args, **kwargs):
        command = pe_command.PortableExecutableBinaryAnalysisCommand()
        command.apply_to(current_program=self.currentProgram, monitor=self.monitor)


# Usage:
pe_script = PE_script()
pe_script.run()  # Run the script
```

Please note that this Python code is equivalent to the given Java code. However, it might not work as expected if you don't have `ghidra` and its related modules installed in your Python environment.