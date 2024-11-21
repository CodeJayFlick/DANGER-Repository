class GhidraFolder:
    def __init__(self, file_manager: 'ProjectFileManager', listener: 'DomainFolderChangeListener'):
        self.file_manager = file_manager
        self.file_system = file_manager.get_local_file_system()
        self.versioned_file_system = file_manager.get_versioned_file_system()
        self.listener = listener
        self.name = FileSystem.SEPARATOR

    def __init__(self, parent: 'GhidraFolder', name: str):
        self.parent = parent
        self.name = name

        if parent:
            self.file_manager = parent.get_project_file_manager()
            self.file_system = parent.get_local_file_system()
            self.versioned_file_system = parent.get_versioned_file_system()
            self.listener = parent.get_listener()

    def get_local_file_system(self):
        return self.file_system

    def get_versioned_file_system(self):
        return self.versioned_file_system

    def get_user_file_system(self):
        return self.file_manager.get_user_file_system()

    def get_listener(self):
        return self.listener

    def get_project_file_manager(self):
        return self.file_manager

    def get_folder_data(self, folder_path: str) -> 'GhidraFolderData':
        if not folder_path.startswith(FileSystem.SEPARATOR):
            parent_data = self.get_root_folder_data()
        else:
            parent_data = self.get_folder_data()

        folder_data = parent_data.get_folder_data(folder_path, False)
        if folder_data is None:
            path = folder_path
            raise FileNotFoundError(f"folder {path} not found")

        return folder_data

    def get_file_data(self, file_name: str) -> 'GhidraFileData':
        try:
            file_data = self.get_folder_data().get_file_data(file_name, False)
        except FileNotFoundException as e:
            raise FileNotFoundException(f"file {self.get_pathname(file_name)} not found")

        return file_data

    def get_root_folder_data(self):
        if self.parent is None:
            return self.file_manager.get_root_folder_data()
        else:
            return self.parent.get_folder_data()

    def create_folder_data(self, folder_name: str) -> 'GhidraFolderData':
        try:
            parent_data = (folder_name.startswith(FileSystem.SEPARATOR)
                           and self.file_manager.get_root_folder_data() or
                           self.get_folder_data())
            if not parent_data.contains(folder_name):
                return parent_data.create_folder(folder_name)

        except InvalidNameException as e:
            raise IOException(e)

    def refresh_folder_data(self) -> None:
        try:
            folder_data = self.get_folder_data()
            folder_data.refresh(False, True)
        except IOException as e:
            pass

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise InvalidNameException("Invalid file name")

        try:
            folder_data = self.get_folder_data()
            folder_data.set_name(value)
        except IOException as e:
            pass

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value: 'GhidraFolder'):
        if not isinstance(value, GhidraFolder):
            raise InvalidNameException("Invalid file name")

        try:
            folder_data = self.get_folder_data()
            folder_data.set_parent(value)
        except IOException as e:
            pass

    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def path(self, value: str):
        if not isinstance(value, str):
            raise InvalidNameException("Invalid file name")

        try:
            folder_data = self.get_folder_data()
            folder_data.set_path(value)
        except IOException as e:
            pass

    def get_pathname(self) -> str:
        return f"{self.parent.path}/{self.name}" if self.parent else FileSystem.SEPARATOR + self.name

    @property
    def is_in_writable_project(self):
        return not self.file_manager.get_local_file_system().is_read_only()

    def __eq__(self, other: 'GhidraFolder'):
        if isinstance(other, GhidraFolder) and self.path == other.path:
            return True
        else:
            return False

    @property
    def project_locator(self):
        return self.file_manager.get_project_locator()
