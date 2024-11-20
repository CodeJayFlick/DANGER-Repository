from typing import Optional, List, Iterator, TypeVar

E = TypeVar('E')

class LazyFluentIterable(E):
    def __init__(self, iterable: Iterable[E]):
        self.iterable = iterable

    @staticmethod
    def from(iterable: Iterable[E]) -> 'LazyFluentIterable[E]':
        return LazyFluentIterable(iterable)

    def filter(self, predicate: Predicate[~E]) -> 'LazyFluentIterable[~E]':
        class FilteringIterator(Iterator[~E]):
            def __init__(self):
                self.from_iterator = iter(self.iterable)
                self.predicate = predicate

            def compute_next(self) -> Optional[~E]:
                while True:
                    candidate = next(self.from_iterator, None)
                    if candidate is not None and self.predicate.test(candidate):
                        return candidate
                    elif candidate is None:
                        return None

        return LazyFluentIterable(FilteringIterator())

    def first(self) -> Optional[E]:
        result_iterator = iter(self.first(1))
        return next(result_iterator, None)

    def first(self, count: int) -> 'LazyFluentIterable[~E]':
        class CountedIterator(Iterator[~E]):
            def __init__(self):
                self.from_iterator = iter(self.iterable)
                self.count = count
                self.current_index = 0

            def compute_next(self) -> Optional[E]:
                while True:
                    if self.current_index < self.count and next(iter(self.from_iterator), None) is not None:
                        candidate = next(self.from_iterator, None)
                        self.current_index += 1
                        return candidate
                    elif self.current_index >= self.count and next(iter(self.from_iterator), None) is not None:
                        return next(self.from_iterator, None)
                    else:
                        return None

        return LazyFluentIterable(CountedIterator())

    def last(self) -> Optional[E]:
        result_iterator = iter(self.last(1))
        return next(result_iterator, None)

    def last(self, count: int) -> 'LazyFluentIterable[~E]':
        class LastedIterator(Iterator[~E]):
            def __init__(self):
                self.from_iterator = iter(self.iterable)
                self.count = count
                self.stop_index = 0
                self.total_elements_count = 0
                self.list = []
                self.current_index = 0

            def compute_next(self) -> Optional[E]:
                if not self.list:
                    for _ in range(len(self.iterable)):
                        self.list.append(next(iter(self.from_iterator), None))
                    self.total_elements_count = len(self.list)
                    self.stop_index = self.total_elements_count - count
                while True:
                    if self.current_index < self.stop_index and next(iter(self.from_iterator), None) is not None:
                        return next(self.from_iterator, None)
                    elif self.current_index >= self.stop_index and next(iter(self.from_iterator), None) is not None:
                        return next(self.from_iterator, None)

        return LazyFluentIterable(LastedIterator())

    def map(self, function: Function[~E]) -> 'LazyFluentIterable[T]':
        class MappingIterator(Iterator[T]):
            def __init__(self):
                self.old_type_iterator = iter(self.iterable)
                self.function = function

            def compute_next(self) -> Optional[T]:
                if next(iter(self.old_type_iterator), None) is not None:
                    candidate = next(self.old_type_iterator, None)
                    return self.function.apply(candidate)
                else:
                    return None

        return LazyFluentIterable(MappingIterator())

    def as_list(self) -> List[E]:
        return list(self.iterable)

    def __iter__(self):
        class DecoratingIterator(Iterator[E]):
            def __init__(self, from_iterator: Iterator[~E]):
                self.from_iterator = from_iterator

            def compute_next(self) -> Optional[E]:
                if next(iter(self.from_iterator), None) is not None:
                    return next(self.from_iterator)
                else:
                    return None

        return DecoratingIterator(self.iterable)

    @property
    def iterator(self):
        return iter(self)
