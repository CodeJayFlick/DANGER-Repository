Here is the translation of the given Java code into Python:

```Python
import os
from typing import List, Dict

class IngestTask:
    def __init__(self,
                 title: str,
                 fid_file: object,
                 library_record: object,
                 folder: object,
                 library_family_name: str,
                 library_version: str,
                 library_variant: str,
                 language_id: str,
                 common_symbols_file: str,
                 fid_service: object,
                 reporter: object):
        self.title = title
        self.fid_file = fid_file
        self.library_record = library_record
        self.folder = folder
        self.library_family_name = library_family_name
        self.library_version = library_version
        self.library_variant = library_variant
        self.language_id = language_id
        self.common_symbols_file = common_symbols_file
        self.fid_service = fid_service
        self.reporter = reporter

    def run(self, monitor):
        try:
            fid_db = self.fid_file.get_fid_db(True)
        except Exception as e:
            print(f"Failed to open FidDb: {self.fid_file.path}")
            return

        common_symbols = self.parse_symbols(monitor)

        programs = []
        monitor.set_message("Finding domain files...")
        monitor.set_indeterminate(True)
        self.find_programs(programs, self.folder, monitor)
        monitor.set_indeterminate(False)

        monitor.set_message("Populating library...")
        result = self.fid_service.create_new_library_from_programs(fid_db,
                                                                   self.library_family_name,
                                                                   self.library_version,
                                                                   self.library_variant,
                                                                   programs,
                                                                   None,
                                                                   language_id=self.language_id,
                                                                   library_record=None if not self.library_record else [self.library_record],
                                                                   common_symbols=common_symbols,
                                                                   monitor=monitor)
        self.reporter.report(result)
        fid_db.save_database("Saving", monitor)

    def parse_symbols(self, monitor):
        if not self.common_symbols_file:
            return None

        with open(self.common_symbols_file, 'r') as file:
            reader = file.readlines()
            res = []
            for line in reader:
                monitor.check_canceled()
                if line.strip():
                    res.append(line)
            return [line.strip() for line in res]

    def find_programs(self, programs: List[object], my_folder: object, monitor):
        if not my_folder:
            return

        files = my_folder.get_files()
        for file in files:
            monitor.check_canceled()
            monitor.increment_progress(1)
            if file.get_content_type() == "PROGRAM_CONTENT_TYPE":
                programs.append(file)

        folders = my_folder.get_folders()
        for folder in folders:
            monitor.check_canceled()
            monitor.increment_progress(1)
            self.find_programs(programs, folder, monitor)


# Example usage
title = "Ingest Task"
fid_file = object()  # Replace with your FidFile instance
library_record = object()  # Replace with your LibraryRecord instance
folder = object()  # Replace with your DomainFolder instance
library_family_name = "Library Family Name"
library_version = "Library Version"
library_variant = "Library Variant"
language_id = "Language ID"
common_symbols_file = "Common Symbols File Path"
fid_service = object()  # Replace with your FidService instance
reporter = object()  # Replace with your Reporter instance

task = IngestTask(title, fid_file, library_record, folder,
                   library_family_name, library_version, library_variant,
                   language_id, common_symbols_file, fid_service, reporter)
monitor = None  # Replace with your TaskMonitor instance
try:
    task.run(monitor)
except Exception as e:
    print(f"Error: {e}")
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an interpretation and may require adjustments based on the specific requirements of your project.

Here are some key differences between the original Java code and this Python version:

1.  **Class Structure**: In Java, classes were defined with `public` access modifiers, while in Python, they can be defined without any explicit access modifier.
2.  **Method Signatures**: Method signatures have been adjusted to conform to Python's syntax. For example, the `run()` method now takes a single argument (`monitor`) instead of two arguments (`TaskMonitor monitor`).
3.  **Exception Handling**: Exception handling has been modified to use Python's built-in exception handling mechanism.
4.  **File Input/Output**: File input/output operations have been rewritten using Python's built-in file I/O functions, such as `open()` and `readlines()`.
5.  **Type Hints**: Type hints have been added to the function signatures for better code readability.

This translation should provide a good starting point for your project. However, you may need to make further adjustments based on specific requirements or edge cases not accounted for in this conversion.