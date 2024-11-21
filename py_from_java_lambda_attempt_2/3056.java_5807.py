Here is the translation of the given Java code into Python:

```Python
import os
import time
from ghidra_framework import GhidraScript, DomainFolder, Program, LanguageCompilerSpecPair
from ghidra_app_util_importer import AutoImporter, MessageLog

class ImportAllProgramsFromADirectoryScript(GhidraScript):
    def run(self):
        directory = input("Please specify the input directory: ")
        
        language = ask_language()
        
        folder = ask_project_folder()

        log = MessageLog()

        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

        for file in files:
            time.sleep(1)
            
            if self.monitor.is_cancelled():
                break

            if file.startswith('.'):
                continue
            
            program = None
            try:
                program = import_file(file)
            except Exception as e:
                print(str(e))

            if not program:
                try:
                    program = AutoImporter.import_by_looking_for_lcs(os.path.join(directory, file), folder, language.get_language(), language.get_compiler_spec(), self, log, self.monitor)
                except Exception as e:
                    print(str(e))
            
            if not program:
                print("Unable to import program from file " + file)

            else:
                #open_program(program)
                program.release(self)

            print(log.toString())
            log.clear()

def ask_directory(prompt="Please specify the input directory:", default=None):
    while True:
        try:
            return os.path.abspath(input(prompt))
        except ValueError as e:
            print("Invalid path. Please enter a valid directory.")

def ask_language():
    # implement this function to get language from user
    pass

def ask_project_folder():
    # implement this function to get project folder from user
    pass

# Helper functions for importing files and opening programs
def import_file(file):
    # implement this function to import file into Ghidra
    pass

def open_program(program):
    # implement this function to open program in Ghidra
    pass
```

Please note that the `ask_language`, `ask_project_folder`, `import_file` and `open_program` functions are not implemented as they were present in Java code. You would need to add your own implementation for these functions based on how you want them to work.

Also, Python does not have direct equivalent of Java's `Thread.sleep()` function. Instead, we use the built-in `time.sleep()` function which takes seconds as an argument.