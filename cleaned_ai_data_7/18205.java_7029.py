# Apache License v2.0: http://www.apache.org/licenses/LICENSE-2.0

class FileInputFactory:
    def get_ts_file_input(self, file_path: str) -> 'TsFileInput':
        # implementation goes here
        pass


from abc import ABC, abstractmethod


class TsFileInput(ABC):
    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def read(self):
        pass
