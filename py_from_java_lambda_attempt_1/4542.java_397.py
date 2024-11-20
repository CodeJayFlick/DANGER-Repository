Here is the translation of the Java code to Python:
```
import os

class FileImporterService:
    def __init__(self):
        pass

    @property
    def description(self) -> str:
        return "Imports external files into program"

    def import_file(self, folder: str, file_path: str) -> None:
        # Assuming DomainFolder is equivalent to a directory path in Python
        domain_folder = os.path.dirname(folder)
        if not os.path.exists(domain_folder):
            os.makedirs(domain_folder)

        with open(file_path, 'rb') as f:
            with open(os.path.join(domain_folder, os.path.basename(file_path)), 'wb') as dest_f:
                dest_f.write(f.read())

    def import_files(self, folder: str, files: list) -> None:
        for file in files:
            self.import_file(folder, file)
```
Note that I made the following assumptions:

* `DomainFolder` is equivalent to a directory path in Python.
* The `importFile` and `importFiles` methods are responsible for copying the files from their original location to the specified Ghidra project folder. In this translation, I used Python's built-in file handling functions (`open`, `read`, `write`) to achieve this.

Please keep in mind that this is a direct translation of the Java code to Python, and you may need to adjust it according to your specific use case or requirements.