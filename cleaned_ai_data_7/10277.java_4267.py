class Path:
    GHIDRA_HOME = "$GHIDRA_HOME"
    USER_HOME = "$USER_HOME"

    def __init__(self, file=None, enabled=True, editable=True, read_only=False):
        self.file = file
        self.isEnabled = enabled
        self.isEditable = editable
        self.isReadOnly = read_only

    @staticmethod
    def resolve_ghidra_home(script_path):
        for root in Application.get_application_root_directories():
            length = len(Path.GHIDRA_HOME)
            relative_path = script_path[length:]
            path_file = ResourceFile(root, relative_path)
            if path_file.exists():
                return path_file
        return None

    def __eq__(self, other):
        if not isinstance(other, Path):
            return False
        that = other
        return self.file == that.file

    def __hash__(self):
        return hash(self.file)

    @property
    def is_read_only(self):
        return self.isReadOnly

    @property
    def is_editable(self):
        return self.isEditable

    @property
    def is_enabled(self):
        return self.isEnabled

    @is_enabled.setter
    def is_enabled(self, value):
        self.isEnabled = value

    @property
    def path(self):
        return self.file

    @path.setter
    def path(self, file):
        if self.isEditable:
            self.file = file
        else:
            raise ValueError("Path is not editable")

    @staticmethod
    def from_path_string(path):
        resource_file = None
        if path.startswith(Path.GHIDRA_HOME):
            resource_file = Path.resolve_ghidra_home(path)
        elif path.startswith(Path.USER_HOME):
            user_home = os.environ.get('USER_HOME')
            length = len(Path.USER_HOME)
            relative_path = path[length:]
            resource_file = ResourceFile(os.path.join(user_home, relative_path))
        else:
            resource_file = ResourceFile(path)

        return resource_file

    @staticmethod
    def to_path_string(file):
        user_home = os.environ.get('USER_HOME')
        absolute_path = file.absolute_path()
        for app_root in Application.get_application_root_directories():
            ghidra_home = app_root.absolute_path()
            if absolute_path.startswith(ghidra_home):
                length = len(ghidra_home)
                relative_path = absolute_path[length:]
                return f"{Path.GHIDRA_HOME}{relative_path}".replace('\\', '/')

        if absolute_path.startswith(user_home):
            length = len(user_home)
            relative_path = absolute_path[length:]
            return f"{Path.USER_HOME}{relative_path}".replace('\\', '/')
        
        return absolute_path.replace('\\', '/')

    def __str__(self):
        return self.to_path_string(self.file)

    @property
    def exists(self):
        return self.file.exists()

    def compare_to(self, p):
        return str(self).compareTo(str(p))
