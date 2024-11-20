class IpswFileSystem:
    def __init__(self, file_system_name: str, provider):
        pass  # equivalent to super(filesystemName, provider)

    @property
    def valid(self) -> bool:
        return False

    def open(self, monitor=None):
        pass  # does nothing yet

    def get_listing(self, directory) -> list:
        return []

    def get_byte_provider(self, file: str, monitor=None) -> bytes:
        return None


# Note that Python doesn't have direct equivalent of Java's annotations.
