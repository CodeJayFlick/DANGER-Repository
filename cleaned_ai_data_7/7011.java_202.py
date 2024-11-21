class ApkFileSystem:
    def __init__(self, file_system_name: str, provider):
        pass  # equivalent to super().__init__()

    @property
    def name(self) -> str:
        return self.file_system_name

    @name.setter
    def name(self, value: str):
        self.file_system_name = value

    @property
    def provider(self) -> object:
        return self._provider

    @provider.setter
    def provider(self, value: object):
        self._provider = value

    def is_valid(self) -> bool:
        return False  # equivalent to isValid()

    def open(self) -> None:
        pass  # equivalent to open()

    def get_listing(self, directory: str) -> list:
        return []  # equivalent to getListing()

    def get_byte_provider(self, file_path: str) -> object:
        return None  # equivalent to getByteProvider()
