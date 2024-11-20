class GFileImpl:
    def __init__(self, file_system: 'GFileSystem', parent_file=None, is_directory=False, length=-1, fsrl=None):
        self.file_system = file_system
        self.fsrl = fsrl
        self.parent_file = parent_file
        self.is_directory = is_directory
        self.length = length

    @staticmethod
    def from_path_string(file_system: 'GFileSystem', path: str, fsrl=None, is_directory=False, length=-1):
        if not fsrl:
            fsrl = get_fsrl_from_parent(file_system, None, path)
        return GFileImpl(file_system, None, is_directory, length, fsrl)

    @staticmethod
    def from_path_string_with_parent(file_system: 'GFileSystem', parent_file=None, path: str, fsrl=None, is_directory=False, length=-1):
        if not fsrl:
            fsrl = get_fsrl_from_parent(file_system, parent_file, path)
        return GFileImpl(file_system, parent_file, is_directory, length, fsrl)

    @staticmethod
    def from_filename(file_system: 'GFileSystem', parent_file=None, filename: str, is_directory=False, length=-1, fsrl=None):
        if not fsrl:
            fsrl = get_fsrl_from_parent(file_system, parent_file, filename)
        return GFileImpl(file_system, parent_file, is_directory, length, fsrl)

    @staticmethod
    def from_fsr(file_system: 'GFileSystem', parent_file=None, fsr: 'FSRL', is_directory=False, length=-1):
        return GFileImpl(file_system, parent_file, is_directory, length, fsr)

    def get_parent_file(self) -> 'GFile':
        return self.parent_file

    def get_name(self) -> str:
        return self.fsrl.name

    def is_directory(self) -> bool:
        return self.is_directory

    def get_length(self) -> int:
        return self.length

    def get_filesystem(self) -> 'GFileSystem':
        return self.file_system

    def __str__(self):
        return self.get_path()

    def get_path(self) -> str:
        return self.fsrl.path

    def set_length(self, length: int):
        self.length = length

    def get_fsrl(self) -> 'FSRL':
        return self.fsrl

    def __hash__(self):
        return hash((self.file_system, self.fsrl.path, self.is_directory))

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, GFileImpl):
            return False
        return (self.file_system == other.get_filesystem() and 
                self.fsrl.path == other.get_fsrl().path and 
                self.is_directory == other.is_directory)

def get_fsrl_from_parent(file_system: 'GFileSystem', parent_file=None, path: str) -> 'FSRL':
    if not parent_file:
        return file_system.get_fsrl_root()
    else:
        return parent_file.fsrl.append_path(path)
