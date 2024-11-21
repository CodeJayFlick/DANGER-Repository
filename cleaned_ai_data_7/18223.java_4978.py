class IBatchDataIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self):
        raise NotImplementedError("Subclasses must implement this method")

    def current_time(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def current_value(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def reset(self):
        raise NotImplementedError("Subclasses must implement this method")

    def total_length(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
