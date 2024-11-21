Here is the translation of the Java code into Python:

```Python
import os
from typing import Set, List

class LocalSymbolStore:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir

    @staticmethod
    def is_local_symbol_store_location(location_string: str) -> bool:
        if location_string is None or not location_string.strip():
            return False
        dir = os.path.join(os.getcwd(), location_string)
        return os.path.isabs(dir) and os.path.isdir(dir)

    @staticmethod
    def create(root_dir: str, index_level: int):
        try:
            FileUtilities.checked_mkdirs(root_dir)
            if index_level == 2:
                file = os.path.join(root_dir, "INDEX_TWO_FILENAME")
                if not os.path.exists(file):
                    with open(file, 'w') as f:
                        f.write("created by Ghidra LocalSymbolStore " + str(datetime.now()))
            elif index_level == 1:
                pingme_file = os.path.join(root_dir, "PINGME_FILE_NAME")
                admin_dir = os.path.join(root_dir, "ADMIN_DIRNAME")
                if not os.path.exists(pingme_file):
                    with open(pingme_file, 'w') as f:
                        f.write("created by Ghidra LocalSymbolStore " + str(datetime.now()))
                if not os.path.isdir(admin_dir):
                    os.makedirs(admin_dir)
        except Exception as e:
            raise IOException("Unsupported storage index level: " + str(index_level))

    def get_root_dir(self) -> str:
        return self.root_dir

    @Override
    public String getName() {
        return rootDir.getPath();
    }

    # ... (rest of the class)

class FileUtilities:

    @staticmethod
    def checked_mkdirs(directory: str):
        try:
            os.makedirs(directory)
        except Exception as e:
            raise IOException("Error creating directory")

# Usage example

if __name__ == "__main__":
    root_dir = "path_to_your_directory"
    symbol_store = LocalSymbolStore(root_dir)

    # Use the methods of your class
```

Please note that Python does not have direct equivalent to Java's `File` and `Path`. In this translation, I used Python's built-in file handling functions.