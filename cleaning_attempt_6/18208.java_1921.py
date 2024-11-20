# Apache License, Version 2.0 (see http://www.apache.org/licenses/LICENSE-2.0)

class FileOutputFactory:
    def get_ts_file_output(self, file_path: str, append: bool) -> 'TsFileOutput':
        # implement your logic here
        pass

from abc import ABC, abstractmethod


class TsFileOutput(ABC):
    @abstractmethod
    def write_to_file(self):  # todo: add implementation
        pass
