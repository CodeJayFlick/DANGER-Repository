from typing import Collection, TypeVar

T = TypeVar('T')

class CallbackAccumulator:
    def __init__(self, consumer: callable) -> None:
        self.consumer = consumer

    def add(self, t: T) -> None:
        self.consumer(t)

    def add_all(self, collection: Collection[T]) -> None:
        for item in collection:
            self.add(item)

    def contains(self, t: T) -> bool:
        return False

    def get(self) -> list:
        return []

    def __iter__(self):
        return iter([])

    def size(self) -> int:
        return 0
