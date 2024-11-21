class UnknownArtStorageModeException(Exception):
    def __init__(self, storage_mode: int) -> None:
        super().__init__(f"Unrecognized storage mode: 0x{storage_mode:x}")
