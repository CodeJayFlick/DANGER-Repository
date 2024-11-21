import io

class IBatchReader:
    def __init__(self):
        pass

    def has_next_batch(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next_batch(self) -> 'BatchData':
        raise NotImplementedError("Subclasses must implement this method")

    def close(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
