from typing import TypeVar, Generic

class QRunnable(Generic[I]):
    def run(self, item: I, monitor=None) -> None:
        pass  # This method should be implemented by subclasses.
