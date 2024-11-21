import jna

class UnknownExImpl:
    def __init__(self, jna_data):
        self.jna_data = jna_data
        self.metadata = None

    def get_pointer(self) -> int:
        return 0

    def set_metadata(self, metadata: 'KeyStore') -> None:
        self.metadata = metadata

    def get_metadata(self) -> 'KeyStore':
        return self.metadata


class KeyStore:
    pass
