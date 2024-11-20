import io

class ILogReader:
    def __init__(self):
        pass

    def close(self) -> None:
        """Release resources occupied by this object."""
        raise NotImplementedError("Subclasses must implement this method")

    def hasNext(self) -> bool:
        """Return whether there exists next log to be read."""
        raise FileNotFoundError("No more logs available")
        # return False  # or True, depending on your implementation

    def next(self) -> io.IOError:
        """Return the next log as a PhysicalPlan"""
        raise NoSuchElementException("There are no more logs") from FileNotFoundError
        # return None  # or some other value, depending on your implementation


class NoSuchElementException(Exception):
    pass
