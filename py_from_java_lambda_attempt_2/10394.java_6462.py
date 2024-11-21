Here is a translation of the Java code into Python:

```Python
class IntIntHashtable:
    def __init__(self):
        self.capacity = 3
        self.indexer = IntKeyIndexer(self.capacity)
        self.values = [0] * self.capacity

    def put(self, key: int, value: int) -> None:
        index = self.indexer.put(key)

        if index >= self.capacity:
            self.grow()

        self.values[index] = value

    def get(self, key: int) -> int:
        try:
            index = self.indexer.get(key)
            return self.values[index]
        except IndexError:
            raise NoValueException("No value for the given key")

    def remove(self, key: int) -> int:
        try:
            index = self.indexer.remove(key)
            if index < 0:
                raise NoValueException("No value for the given key")
            return self.values[index]
        except IndexError:
            raise NoValueException("No value for the given key")

    def removeAll(self):
        self.indexer.clear()

    def contains(self, key: int) -> bool:
        try:
            if self.indexer.get(key) >= 0:
                return True
            else:
                return False
        except IndexError:
            raise NoValueException("No value for the given key")

    @property
    def size(self):
        return self.indexer.size

    def get_keys(self):
        return self.indexer.keys


class IntKeyIndexer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.keys = [0] * (capacity + 1)

    def put(self, key: int) -> int:
        index = hash(key)
        if abs(index) > len(self.keys) // 2:
            return -index % len(self.keys)
        else:
            return index

    def get(self, key: int) -> int:
        try:
            return self.put(key)
        except ValueError:
            raise NoValueException("No value for the given key")

    def remove(self, key: int) -> int:
        try:
            return self.get(key)
        except IndexError:
            raise NoValueException("No value key is not found in the table")
        except ValueError:
            raise NoValueException("No value for the given key")

    @property
    def size(self):
        count = 0
        for i in range(len(self.keys)):
            if self.keys[i] != 0:
                count += 1
        return count

    def clear(self) -> None:
        self.keys.fill(0)

    @property
    def keys(self):
        return list(range(len(self.keys)))

class NoValueException(Exception):
    pass


# Example usage:

table = IntIntHashtable()
try:
    table.put(10, 20)
    print(table.get(10))  # prints: 20

except Exception as e:
    print(f"An error occurred: {e}")

print("Table size:", table.size)