class VersionStoreException(Exception):
    def __init__(self):
        super().__init__()

    @classmethod
    def with_message_and_cause(cls, message: str, cause: Exception) -> 'VersionStoreException':
        return cls(message, cause)

    @classmethod
    def with_message(cls, message: str) -> 'VersionStoreException':
        return cls(message)

    @classmethod
    def with_cause(cls, cause: Exception) -> 'VersionStoreException':
        return cls(cause)
