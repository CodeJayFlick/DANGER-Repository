Here is a translation of the provided Java code into equivalent Python:

```Python
import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model import Program
from ghidra.util.exception import CancelledException, VersionException
from ghidra.framework.model import *
from ghidra. program.database import ProgramContentHandler

class CallAnotherScriptForAllPrograms(GhidraScript):
    def __init__(self):
        self.SUBSCRIPT_NAME = "AddCommentToProgramScript.py"

    @Override
    def run(self) -> None:
        if current_program is not None:
            print("This script should be run from a tool with no open programs")
            return

        project = state.get_project()
        project_data = project.get_project_data()
        root_folder = project_data.get_root_folder()

        self.recurse_project_folder(root_folder)

    def recurse_project_folder(self, domain_folder: DomainFolder) -> None:
        files = domain_folder.get_files()
        for file in files:
            self.process_domain_file(file)
        folders = domain_folder.get_folders()
        for folder in folders:
            self.recurse_project_folder(folder)

    def process_domain_file(self, domain_file: DomainFile) -> None:
        if not ProgramContentHandler.PROGRAM_CONTENT_TYPE == domain_file.get_content_type():
            return  # skip non-Program files

        if domain_file.is_versioned() and not domain_file.is_checked_out():
            print(f"WARNING! Skipping versioned file - not checked-out: {domain_file.path_name}")
            return

        program = None
        try:
            program = (Program)(domain_file.get_domain_object(self, True, False))
            self.process_program(program)
        except VersionException as e:
            print(f"ERROR! Failed to process file due to upgrade issue: {domain_file.path_name}")

    def process_program(self, program: Program) -> None:
        try:
            new_state = GhidraState(state.get_tool(), state.get_project(), program, None, None)
            self.run_script(self.SUBSCRIPT_NAME, new_state)
        except Exception as e:
            print(f"ERROR! Exception occurred while processing file: {program.domain_file.path_name}")
            print(e.message)
            e.print_stacktrace()
```

Please note that Python does not support direct translation of Java code. It's a different language with its own syntax and semantics. The above code is an equivalent implementation in Python, but it may not be identical to the original Java code.