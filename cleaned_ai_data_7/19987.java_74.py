from typing import Iterable, Iterator, TypeVar

T = TypeVar('T')

class EnumerationIterable(Iterable[T]):
    def __init__(self, e: 'java.util.Enumeration[typing.Any]' | None) -> None:
        self.e = e

    def iterator(self) -> Iterator[T]:
        if self.e is None:
            return iter(())

        class EnumIterator(Iterator[T]):
            def __init__(self, enumeration: 'java.util.Enumeration[typing.Any]') -> None:
                self.enumeration = enumeration
                self.hasNext = True

            def hasNext(self) -> bool:
                return self.enumeration.hasMoreElements()

            def next(self) -> T:
                if not self.hasNext:
                    raise StopIteration
                return self.enumeration.nextElement()

        return EnumIterator(self.e)
