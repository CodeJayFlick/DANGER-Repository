class FileBytesAdapterNoTable:
    def __init__(self, handle):
        pass  # Equivalent to super(handle)

    def create_file_bytes(self, filename: str, offset: int, size: int, input_stream) -> None:
        raise Exception("Not implemented")

    def get_buffer(self, i: int) -> None:
        return None

    def get_all_file_bytes(self) -> list:
        return []

    def refresh(self):
        pass  # Equivalent to do nothing

    def delete_file_bytes(self, file_bytes: 'FileBytes') -> bool:
        return False
