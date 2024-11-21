class SleighCompilerSpecDescription:
    def __init__(self, id: str, name: str, file_path: str):
        self.id = id
        self.name = name
        self.file = open(file_path, 'r')

    @property
    def file(self) -> object:
        return self._file

    @file.setter
    def file(self, value: object):
        self._file = value

    def get_source(self) -> str:
        return self.file.read()
