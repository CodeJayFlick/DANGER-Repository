from typing import List, Any, TypeVar
import itertools

T = TypeVar('T')

class MultiIterator:
    def __init__(self, iterators: List[Any], comparator=None, forward=True):
        self.iterators = iterators
        if not comparator and any(not isinstance(i, list) for i in iterators):
            raise ValueError("At least one iterator must be a list")
        self.comparator = comparator or (lambda x, y: -1 if x > y else 0 if x == y else 1)
        self.forward = forward

    def remove(self):
        raise NotImplementedError()

    def __iter__(self):
        return self

    def __next__(self) -> Any:
        while True:
            lowest = None
            for iterator in self.iterators:
                try:
                    t = next(iterator)
                except StopIteration:
                    continue
                if not lowest or self.comparator(lowest, t) > 0:
                    lowest = t
            if lowest is None:
                raise AssertionError("next() has no more items to give! Call hasNext() before calling next()")
            for iterator in self.iterators:
                try:
                    t = next(iterator)
                except StopIteration:
                    continue
                if self.comparator(lowest, t) == 0:
                    return lowest
        raise AssertionError("next() has no more items to give! Call hasNext() before calling next()")

    def __bool__(self):
        for iterator in self.iterators:
            try:
                next(iterator)
                return True
            except StopIteration:
                pass
        return False

class TComparator:
    @staticmethod
    def compare(t1: Any, t2: Any) -> int:
        if not isinstance(t1, comparable_type):
            raise AssertionError("T must be comparable")
        if not isinstance(t2, comparable_type):
            raise AssertionError("T must be comparable")
        return (t1).compareTo(t2)

class ReverseComparatorWrapper:
    def __init__(self, comparator: Any):
        self.comparator = comparator

    @staticmethod
    def compare(t1: Any, t2: Any) -> int:
        return -comparator.compare(t1, t2)
