import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.util.exception import CancelledException
from ghidra.framework.model import *
from ghidra.program.model.mem import Memory

class GetSymbolForDynamicAddress(GhidraScript):
    def __init__(self):
        self.address_to_look_for = None
        self.found_symbol = False
        self.programs_with_address = []

    def run(self):
        try:
            self.address_to_look_for = ask_address("Enter Dynamic Address", "Please enter the address you want to find a symbol for: ")
        except CancelledException as e:
            print("User cancelled script")
            return

        firmware_version = current_program.get_domain_file().get_pathname().split("/")[1]
        project = state.get_project()
        project_data = project.get_project_data()
        root_folder = project_data.get_root_folder()
        folder = root_folder.get_folder(firmware_version)
        if folder is None:
            print("Run this script from a program under an iOS firmware directory.")
            return
        self.process_folder(folder)

        if not self.found_symbol:
            self.print_failure_explanation()

    def process_folder(self, domain_folder):
        if self.found_symbol:
            return

        folders = domain_folder.get_folders()
        for folder in folders:
            self.process_folder(folder)
        files = domain_folder.get_files()
        for file in files:
            self.process_file(file)

    def process_file(self, domain_file):
        if self.found_symbol:
            return
        try:
            domain_object = domain_file.get_domain_object(True, False, monitor)
            if isinstance(domain_object, Program):
                program = domain_object
                self.process_program(program)
        except Exception as e:
            print(e)

    def process_program(self, program):
        if self.found_symbol:
            return

        memory = program.get_memory()
        if memory.contains(self.address_to_look_for):
            self.programs_with_address.append(program.get_name())
            listing = program.get_listing()
            function = listing.get_function_at(self.address_to_look_for)
            if function is None:
                return
            name = function.get_name()
            self.demangle_and_create_symbol(name)

            self.found_symbol = True

    def demangle_and_create_symbol(self, name):
        try:
            create_label(self.address_to_look_for, name, True)
            print(f"Created symbol \"{name}\" for address: {self.address_to_look_for}")
        except Exception as e:
            print(e)
            print(f"Tried to create symbol \"{name}\" for address {self.address_to_look_for}")

    def print_failure_explanation(self):
        if len(self.programs_with_address) != 0:
            print(f"No function existed at the address {self.address_to_look_for}")
            print("The programs that contain the address are:")
            for name in self.programs_with_address:
                print(f"\t{name}")
        else:
            print("Didn't find any programs that contain that address")
