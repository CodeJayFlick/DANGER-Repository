class TraceChangeType:
    def __init__(self):
        pass

    def get_type(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_sub_type(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
