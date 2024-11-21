import ghidra.app.cmdformats.portableexecutablebinaryanalysiscommand as pe_command
from ghidra.app.script import GhidraScript


class PE_script(GhidraScript):
    def run(self, *args, **kwargs):
        command = pe_command.PortableExecutableBinaryAnalysisCommand()
        command.apply_to(current_program=self.currentProgram, monitor=self.monitor)


# Usage:
pe_script = PE_script()
pe_script.run()  # Run the script
