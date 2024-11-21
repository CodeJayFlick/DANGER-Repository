import os
from ghidra_script import GhidraScript
from ghidra.program.model.data import *
from ghidra.util import UniversalID

class CompareGDTs(GhidraScript):
    def __init__(self):
        self.first_file = None
        self.second_file = None
        self.output_file = None
        self.first_archive = None
        self.second_archive = None
        self.print_writer = None
        self.match_by_name = False
        self.check_pointers = False
        self.check_arrays = False

    def run(self):
        self.first_file = ask_file("Select First GDT File", "Select 1st")
        self.second_file = ask_file("Select Second GDT File", "Select 2nd")
        self.output_file = ask_file("Select Output File", "Select output file")

        if os.path.exists(self.output_file):
            overwrite = ask_yes_no("Overwrite existing output file?",
                                    "The specified output file already exists. \nDo you want to overwrite it?")
            if not overwrite:
                print(f"Output file {self.output_file} already exists. User aborted...")
                return

        self.match_by_name = ask_yes_no("Match Data Types By Path Name?",
                                         "Do you want to match data types by their path names (rather than by Universal ID)?")
        self.check_pointers = ask_yes_no("Check Pointers?", "Do you want to check Pointers?")
        self.check_arrays = ask_yes_no("Check Arrays?", "Do you want to check Arrays")

        self.first_archive = FileDataTypeManager.open_file_archive(self.first_file, False)
        self.second_archive = FileDataTypeManager.open_file_archive(self.second_file, False)
        self.print_writer = open(self.output_file, 'w')

        try:
            self.compare_data_types()
        finally:
            if self.print_writer:
                self.print_writer.close()

    def output(self, message):
        print(message)

    def compare_data_types(self):
        self.output(f"\nComparing {self.first_file} \n         & {self.second_file}.")
        
        only_in_first = 0
        for dataType in self.first_archive.get_all_data_types():
            if not self.check_pointers and isinstance(dataType, Pointer):
                continue

            if not self.check_arrays and isinstance(dataType, Array):
                continue
            
            matchingDataType = self.get_matching_dtype(dataType, self.second_archive)
            
            if matchingDataType is None:
                pathName = dataType.path_name
                print(pathName)
                only_in_first += 1
        
        self.output(f"{only_in_first} data types that were only in first archive.")

        only_in_second = 0
        for dataType in self.second_archive.get_all_data_types():
            if not self.check_pointers and isinstance(dataType, Pointer):
                continue

            if not self.check_arrays and isinstance(dataType, Array):
                continue
            
            matchingDataType = self.get_matching_dtype(dataType, self.first_archive)
            
            if matchingDataType is None:
                pathName = dataType.path_name
                print(pathName)
                only_in_second += 1
        
        self.output(f"{only_in_second} data types that were only in second archive.")

        different_kinds = 0
        for dataType in self.first_archive.get_all_data_types():
            if not self.check_pointers and isinstance(dataType, Pointer):
                continue

            if not self.check_arrays and isinstance(dataType, Array):
                continue
            
            matchingDataType = self.get_matching_dtype(dataType, self.second_archive)
            
            if matchingDataType is not None:
                dtClass = dataType.__class__
                sameNamedDtClass = matchingDataType.__class__

                if dtClass != sameNamedDtClass:
                    message = f"{dataType.path_name} ({dtClass.__name__}) vs ({sameNamedDtClass.__name__})"
                    print(message)
                    different_kinds += 1
        
        self.output(f"{different_kinds} data types had different kinds.")

    def get_matching_dtype(self, dataType, dtmArchive):
        if not self.match_by_name:
            universalID = dataType.universal_id
            return dtmArchive.find_data_type_for_id(universalID) if universalID else None

        return dtmArchive.get_data_type(dataType.category_path, dataType.name)

    def ask_file(self, message1, message2):
        # Implement this method to get the file path from user input.
        pass

    def ask_yes_no(self, question, default="yes"):
        # Implement this method to get yes/no answer from user input.
        pass
