from typing import TypeVar, Any

T = TypeVar('T')

class AsyncResult:
    def __init__(self):
        pass

    @property
    def is_completed(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_value(self) -> T | None:
        raise NotImplementedError("Subclasses must implement this method")

    def await(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
