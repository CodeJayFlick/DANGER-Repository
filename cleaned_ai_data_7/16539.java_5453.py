class IMultBatchReader:
    def __init__(self):
        pass

    def has_next_batch(self, full_path: str) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next_batch(self, full_path: str) -> 'BatchData':
        raise NotImplementedError("Subclasses must implement this method")
