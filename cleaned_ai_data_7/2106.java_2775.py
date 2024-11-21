from typing import Any, TypeVar

R = TypeVar('R')

class AsyncSequenceHandler:
    def __init__(self):
        pass

    def next(self, v: Any, exc: Exception) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def next_ignore(self, result: Any, exc: Exception) -> None:
        self.next(None, exc)
