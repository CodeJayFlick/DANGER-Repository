class Node:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_type(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")
