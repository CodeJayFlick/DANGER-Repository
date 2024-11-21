class ProjectLocator:
    PROJECT_FILE_SUFFIX = ".gpr"
    PROJECT_DIR_SUFFIX = ".rep"
    LOCK_FILE_SUFFIX = ".lock"

    def __init__(self, path: str, name: str):
        self.name = name
        if not name.endswith(self.PROJECT_FILE_SUFFIX):
            return

        self.name = name[:-len(self.PROJECT_FILE_SUFFIX)]
        self.location = path
        if not self.location:
            self.location = "/tmp"

        self.url = GhidraURL.make_url(self.location, name)

    def is_transient(self) -> bool:
        return False

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value: URL):
        self._url = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def location(self):
        return self._location

    @location.setter
    def location(self, value: str):
        self._location = value

    def get_project_dir(self) -> 'os.path.Path':
        from os import path as osp
        return osp.join(self.location, f"{self.name}{self.PROJECT_DIR_SUFFIX}")

    def get_marker_file(self) -> 'os.path.Path':
        from os import path as osp
        return osp.join(self.location, f"{self.name}{self.PROJECT_FILE_SUFFIX}")

    def get_project_lock_file(self) -> 'os.path.Path':
        from os import path as osp
        return osp.join(self.location, f"{self.name}{self.LOCK_FILE_SUFFIX}")

    @staticmethod
    def get_project_dir_extension() -> str:
        return ProjectLocator.PROJECT_DIR_SUFFIX

    def __eq__(self, other):
        if not isinstance(other, ProjectLocator):
            return False

        return self.name == other.name and self.location == other.location

    def __hash__(self) -> int:
        return hash((self.name, self.location))

    def __str__(self) -> str:
        from ghidra.url import GhidraURL
        return GhidraURL.display_string(self.url)

    @staticmethod
    def get_project_extension() -> str:
        return ProjectLocator.PROJECT_FILE_SUFFIX

    @staticmethod
    def is_project_dir(file: 'os.path.Path') -> bool:
        if not file.is_directory():
            return False

        return file.name.endswith(ProjectLocator.PROJECT_DIR_SUFFIX)

    def exists(self) -> bool:
        from os import path as osp
        return self.get_marker_file().isfile() and self.get_project_dir().isdir()
