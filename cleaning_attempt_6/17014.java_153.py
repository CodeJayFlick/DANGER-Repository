import logging
from abc import ABCMeta, abstractmethod
from typing import List, Collection

class ModificationFile:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.modifications = None
        self.writer = LocalTextModificationAccessor(file_path)
        self.reader = LocalTextModificationAccessor(file_path)

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(__name__)

    def init(self):
        if not self.modifications:
            self.modifications = self.reader.read()

    def check_init(self):
        if not self.modifications:
            self.init()

    def close(self):
        try:
            self.writer.close()
            self.modifications = None
        except Exception as e:
            logging.error("Error closing modification file: %s", str(e))

    def abort(self):
        if self.modifications and len(self.modifications) > 0:
            self.writer.abort()
            self.modifications.pop()

    def write(self, mod: 'Modification') -> None:
        try:
            self.check_init()
            self.writer.write(mod)
            self.modifications.append(mod)
        except Exception as e:
            logging.error("Error writing modification to file: %s", str(e))

    def get_modifications(self) -> Collection['Modification']:
        try:
            self.check_init()
            return list(self.modifications)
        except Exception as e:
            logging.error("Error getting modifications from file: %s", str(e))

    @property
    def path(self):
        return self.file_path

    @path.setter
    def set_path(self, value: str) -> None:
        self.file_path = value

    def remove(self) -> None:
        try:
            self.close()
            import os
            os.remove(self.file_path)
        except Exception as e:
            logging.error("Error removing modification file: %s", str(e))

    def exists(self) -> bool:
        return os.path.exists(self.file_path)

    def create_hardlink(self) -> 'ModificationFile':
        if not self.exists():
            return None

        while True:
            hardlink_suffix = f"{os.path.sep}{int(time.time())}_{random.randint(0, 2**31-1)}"
            hardlink_file = os.path.join(os.path.dirname(self.file_path), hardlink_suffix)

            try:
                os.link(self.file_path, hardlink_file)
                return ModificationFile(hardlink_file)
            except FileExistsError as e:
                # retry a different name if the file is already created
                pass
            except Exception as e:
                logging.error("Cannot create hardlink for %s: %s", self.file_path, str(e))
                return None

    @staticmethod
    def get_normal_mods(ts_file_resource) -> 'ModificationFile':
        return ModificationFile(f"{ts_file_resource.get_ts_file_path()}{.FILE_SUFFIX}")

    @staticmethod
    def get_compaction_mods(ts_file_resource) -> 'ModificationFile':
        return ModificationFile(f"{ts_file_resource.get_ts_file_path()}{.COMPACTION_FILE_SUFFIX}")
