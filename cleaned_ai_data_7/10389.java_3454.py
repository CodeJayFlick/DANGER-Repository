class IndexRangeIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        """Returns true if there are more index ranges."""
        return True  # This should be implemented based on your actual data structure.

    def next(self) -> 'IndexRange':
        """Returns the next index range."""
        raise NotImplementedError("Subclass must implement this method.")
