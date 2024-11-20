Here is the translation of the given Java code into Python:

```Python
import os
from ghidra_bridge import GhidraBridge


class FindFunctionByHash:
    def __init__(self):
        self.service = None

    def run(self):
        try:
            self.service = FidService()
            
            folder_path = ask_project_folder("Please select a project folder to RECURSIVELY look for a named function:")
            hash_string = ask_string("Please enter function hash", "Please enter the (hex) function hash you're looking for:")
            hash_value = int(hash_string, 16)
            choices = [HashLookupListMode.FULL, HashLookupListMode.SPECIFIC]
            hash_type = ask_choice("Please choose hash type", "Please select the type of hash", choices, choices[1])

            programs = []
            self.find_programs(programs, folder_path)

            self.find_function(programs, hash_value, hash_type)
        except Exception as e:
            print(f"An error occurred: {e}")

    def find_function(self, programs, hash_value, hash_type):
        for program in programs:
            if monitor.is_cancelled():
                return
            try:
                function_manager = program.get_domain_object().get_function_manager()
                functions = function_manager.get_functions(True)
                for function in functions:
                    if monitor.is_cancelled():
                        return
                    fid_hash_quad = self.service.hash_function(function)
                    if fid_hash_quad is None:
                        continue
                    if (hash_type == HashLookupListMode.FULL and fid_hash_quad.full_hash == hash_value) or \
                       (hash_type == HashLookupListMode.SPECIFIC and fid_hash_quad.specific_hash == hash_value):
                        print(f"found {function.name} at {function.entry_point} in {program.path}")
            except Exception as e:
                print(f"problem looking at {program.name}: {e}")

    def find_programs(self, programs, folder_path):
        for file_name in os.listdir(folder_path):
            if monitor.is_cancelled():
                return
            full_file_path = os.path.join(folder_path, file_name)
            if os.path.isfile(full_file_path) and "PROGRAM_CONTENT_TYPE" == self.get_content_type(full_file_path):
                programs.append(full_file_path)

        for folder in [os.path.join(folder_path, f) for f in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, f))]:
            if monitor.is_cancelled():
                return
            self.find_programs(programs, folder)


    def ask_project_folder(self):
        # implement this method to get the project folder path from user input

    def ask_string(self, prompt1, prompt2):
        # implement this method to get a string value from user input

    def ask_choice(self, prompt1, prompt2, choices, default):
        # implement this methods to get a choice from user input

    def get_content_type(self, file_path):
        # implement this method to determine the content type of a given file
```

Please note that you need to implement `ask_project_folder`, `ask_string`, and `ask_choice` methods in your Python code. These are placeholders for getting user inputs from console or GUI.

Also, please ensure that all necessary libraries (like ghidra_bridge) are installed before running this script.