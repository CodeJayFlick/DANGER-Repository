Here is the translation of the Java code into Python:

```Python
import os
from collections import defaultdict

class ModuleManifestFile:
    MODULE_MANIFEST_FILE_NAME = "Module.manifest"
    NAME_IDENTIFIER = "#NAME:"
    DEPENDENCY_IDENTIFIER = "#DEPENDENCY:"
    MODULE_FILE_LICENSE = "#MODULE FILE LICENSE:"
    EXCLUDE_FROM_GHIDRA_JAR = "#EXCLUDE FROM GHIDRA JAR"
    DATA_SEARCH_IGNORE_DIR = "#DATA SEARCH IGNORE DIR:"
    MODULE_DIR_IDENTIFER = "#MODULE DIR:"
    FAT_JAR = "#FAT JAR:"

    def __init__(self, module_root_dir):
        self.module_name = None
        self.exclude_from_ghidra_jar = False
        self.file_ip_map = defaultdict(str)
        self.data_search_ignore_dirs = set()
        self.fat_jars = set()

        if not os.path.exists(module_root_dir):
            raise FileNotFoundError(f"Module root directory '{module_root_dir}' does not exist")

        file_path = os.path.join(module_root_dir, self.MODULE_MANIFEST_FILE_NAME)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Missing module manifest file: {file_path}")

        with open(file_path) as f:
            lines = [line.strip() for line in f.readlines()]

        for i, line in enumerate(lines, start=1):
            self.process_line(line, i)

    def process_line(self, config_line, line_number):
        trimmed_line = config_line.strip()
        if not trimmed_line:
            return

        elif trimmed_line.startswith(self.NAME_IDENTIFIER):
            self.module_name = trimmed_line[len(self.NAME_IDENTIFIER):].strip()

        elif trimmed_line.startswith(self.DEPENDENCY_IDENTIFIER):
            pass  # ignore for now

        elif trimmed_line.startswith(self.EXCLUDE_FROM_GHIDRA_JAR):
            self.exclude_from_ghidra_jar = True

        elif trimmed_line.startswith(self.MODULE_FILE_LICENSE):
            file_and_ip_line = trimmed_line[len(self.MODULE_FILE_LICENSE):].strip()
            first_space = file_and_ip_line.find(' ')
            if first_space < 0:
                raise ValueError(f"Invalid module manifest entry for identifier '{self.MODULE_FILE_LICENSE}'")

            filename = file_and_ip_line[:first_space]
            ip = file_and_ip_line[first_space + 1:]
            self.file_ip_map[filename] = ip

        elif trimmed_line.startswith(self.DATA_SEARCH_IGNORE_DIR):
            ignore_dir_name = trimmed_line[len(self.DATA_SEARCH_IGNORE_DIR):].strip()
            self.data_search_ignore_dirs.add(ignore_dir_name)

        elif trimmed_line.startswith(self.MODULE_DIR_IDENTIFER):
            pass  # do nothing for now

        elif trimmed_line.startswith(self.FAT_JAR):
            fat_jar = trimmed_line[len(self.FAT_JAR):].strip()
            self.fat_jars.add(fat_jar)

        else:
            message = f"Module manifest file error on line {line_number} of file: {file_path}\n\t-> Invalid line encountered: {trimmed_line}"
            print(message, flush=True)  # equivalent to Msg.debug(this, message);

    @property
    def module_name(self):
        return self.module_name

    @property
    def exclude_from_ghidra_jar(self):
        return self.exclude_from_ghidra_jar

    @property
    def file_ip_map(self):
        return dict(self.file_ip_map)

    @property
    def data_search_ignore_dirs(self):
        return self.data_search_ignore_dirs.copy()

    @property
    def fat_jars(self):
        return self.fat_jars.copy()
```

Please note that Python does not have direct equivalent of Java's `HashMap` and `HashSet`. Instead, we use a dictionary (`defaultdict`) for the file IP map and sets (converted to lists) for data search ignore dirs and fat jars.