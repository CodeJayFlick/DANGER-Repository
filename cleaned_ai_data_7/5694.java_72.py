class GFileSystemBase:
    def __init__(self, file_system_name: str, provider):
        self.file_system_name = file_system_name
        self.provider = provider

    @property
    def fsrl(self) -> 'FSRLRoot':
        return self._fsrl

    @fsrl.setter
    def fsrl(self, value: 'FSRLRoot'):
        self.root = GFileImpl(self, None, True, -1, value.with_path('/'))
        self._fsrl = value

    @property
    def filesystem_service(self) -> 'FileSystemService':
        return self._filesystem_service

    @filesystem_service.setter
    def filesystem_service(self, value: 'FileSystemService'):
        self._filesystem_service = value

    def __str__(self):
        return f"File system {type(self).__name__} - {self.description()} - {self.name}"

    def is_valid(self) -> bool:
        raise NotImplementedError("is_valid method must be implemented")

    def open(self, monitor: 'TaskMonitor') -> None:
        raise NotImplementedError("open method must be implemented")

    def close(self):
        self.ref_manager.on_close()
        if self.provider is not None:
            try:
                self.provider.close()
            except Exception as e:
                print(f"Error closing provider: {e}")
        self.provider = None

    @property
    def closed(self) -> bool:
        return self.provider is None

    @property
    def name(self):
        return self.file_system_name

    def get_listing(self, directory: 'GFile') -> List['GFile']:
        raise NotImplementedError("get_listing method must be implemented")

    def debug(self, bytes: bytearray, file_name: str) -> None:
        if SystemUtilities.is_in_development_mode():
            temp_file = tempfile.TemporaryFile()
            try:
                out = BytesIO(bytes)
                shutil.copyfileobj(out, temp_file)
            finally:
                temp_file.close()

    def lookup(self, path: str) -> 'GFile':
        if not path or path == '/':
            return self.root
        parts = path.split('/')
        current = None
        for part in parts:
            if not part:
                continue
            listing = self.get_listing(current)
            for gf in listing:
                if part == gf.name:
                    current = gf
                    break
            else:
                return None
        return current

    @property
    def ref_manager(self) -> 'FileSystemRefManager':
        return self._ref_manager


class FSRLRoot:
    pass


class FileSystemService:
    pass


class GFileImpl:
    pass


def system_utilities_is_in_development_mode() -> bool:
    # implement this method according to your needs
    raise NotImplementedError("system_utilities_is_in_development_mode must be implemented")
