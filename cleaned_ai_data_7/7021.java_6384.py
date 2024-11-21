class ArtCompression:
    def __init__(self):
        pass

    def get_storage_mode(self) -> int:
        raise UnknownArtStorageModeException("Unknown storage mode")

    def get_compressed_size(self) -> int:
        return 0

    def get_compressed_offset(self) -> int:
        return 0

    def get_decompressed_size(self) -> int:
        return 0

    def get_decompressed_offset(self) -> int:
        return 0


class UnknownArtStorageModeException(Exception):
    pass
