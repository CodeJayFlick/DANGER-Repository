Here is the translation of the given Java code into equivalent Python:

```Python
import os
from typing import Set, List

class FidFile:
    def __init__(self, fid_file_manager: 'FidFileManager', file: str, is_installed: bool):
        self.fid_file_manager = fid_file_manager
        self.file = file
        self.is_installed = is_installed
        self.active = True
        self.open_updateable_fid_db = None

    def isValidFile(self) -> bool:
        try:
            _ = get_fid_db(self, False)
            return True
        except (VersionException, IOException):
            Msg.showError(self, "Failed to open FidDb", f"Failed to open incompatible FidDb (may need to regenerate with this version of Ghidra): {self.file}")
            return False

    def setActive(self, b: bool) -> None:
        self.active = b
        self.fid_file_manager.active_state_changed(self)

    def get_fid_db(self, open_for_update: bool) -> 'FidDB':
        if open_for_update and self.open_updateable_fid_db is not None:
            self.open_updateable_fid_db.increment_open_count()
            return self.open_updateable_fid_db
        fid_db = FidDB(self, open_for_update)
        if open_for_update:
            self.open_updateable_fid_db = fid_db
        if self.supported_languages is None:
            self.supported_languages = get_supported_languages(fid_db)
        return fid_db

    def get_file(self) -> str:
        return self.file

    def __str__(self) -> str:
        return self.get_name()

    @property
    def installed(self) -> bool:
        return self.is_installed

    @property
    def active_state(self) -> bool:
        return self.active

    def get_path(self) -> str:
        return os.path.abspath(self.file)

    def __eq__(self, other: 'FidFile') -> bool:
        if not isinstance(other, FidFile):
            return False
        return self.file == other.file

    def __hash__(self) -> int:
        return hash(self.file)

    @property
    def name(self) -> str:
        return os.path.basename(self.file)

    @property
    def base_name(self) -> str:
        return os.path.splitext(os.path.basename(self.file))[0]

    def can_process_language(self, language: 'Language') -> bool:
        if self.supported_languages is None:
            self.supported_languages = get_supported_languages()
        return self.supported_languages.get(language.language_description)

def get_fid_db(fid_file: FidFile, open_for_update: bool) -> 'FidDB':
    # implementation

class ProcessorSizeComparator:
    def compare(self, o1: 'LanguageDescription', o2: 'LanguageDescription') -> int:
        # implementation
```

Note that Python does not have direct equivalent of Java's `package` and `import`, so I've removed them. Also, the translation is based on my understanding of the code, if there are any errors or missing parts please let me know.