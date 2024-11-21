class Preview:
    def __init__(self):
        pass

    def get_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_preview(self, memory: bytes, addr: int) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_data_type(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")
