Here is the translation of the given Java code into Python:

```Python
from typing import Iterator

class DirectedLongKeyIterator:
    @staticmethod
    def get_iterator(table: dict, key_range: tuple, direction: str) -> Iterator[int]:
        min_key = int(min(key_range))
        max_key = int(max(key_range))

        if direction == 'forward':
            return ForwardLongKeyIterator(table.get_long_keys(min_key, max_key, min_key))
        else:
            return BackwardLongKeyIterator(table.get_long_keys(min_key, max_key, max_key))


class ForwardLongKeyIterator(Iterator[int]):
    def __init__(self, long_keys: list):
        self.long_keys = long_keys
        self.index = 0

    def next(self) -> int:
        if not self.hasNext():
            raise StopIteration
        result = self.long_keys[self.index]
        self.index += 1
        return result


class BackwardLongKeyIterator(Iterator[int]):
    def __init__(self, long_keys: list):
        self.long_keys = long_keys
        self.index = len(self.long_keys) - 1

    def next(self) -> int:
        if not self.hasNext():
            raise StopIteration
        result = self.long_keys[self.index]
        self.index -= 1
        return result


class Table:
    @staticmethod
    def get_long_keys(min_key: int, max_key: int, start_key: int) -> list[int]:
        # Implement your logic to retrieve long keys from the table based on min_key, max_key and start_key.
        pass

```

Please note that Python does not have direct equivalent of Java's `Direction` enum. I used a string 'forward' or 'backward' as an alternative in this translation. Also, you need to implement your logic for retrieving long keys from the table based on min_key, max_key and start_key in the `Table.get_long_keys()` method.