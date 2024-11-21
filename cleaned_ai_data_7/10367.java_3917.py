from collections import deque
from typing import TypeVar, Collection, Iterator

T = TypeVar('T')

class Accumulator:
    def __init__(self):
        self.data: list[T] = []

    def add(self, t: T) -> None:
        """Add an element to the accumulator."""
        self.data.append(t)

    def add_all(self, collection: Collection[T]) -> None:
        """Add all elements from a collection to the accumulator."""
        self.data.extend(collection)

    def contains(self, t: T) -> bool:
        """Check if an element is in the accumulator."""
        return t in self.data

    def get(self) -> list[T]:
        """Get the accumulated data as a list."""
        return self.data.copy()

    def size(self) -> int:
        """Get the number of elements in the accumulator."""
        return len(self.data)

    @property
    def empty(self) -> bool:
        """Check if the accumulator is empty."""
        return not self.size()

    def __iter__(self) -> Iterator[T]:
        """Make the Accumulator iterable."""
        yield from self.get()
