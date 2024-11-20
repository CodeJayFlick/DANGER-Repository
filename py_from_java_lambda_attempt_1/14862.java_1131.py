Here is the translation of the given Java code into Python:

```Python
class Saga:
    def __init__(self):
        self.chapters = []

    def chapter(self, name: str) -> 'Saga':
        self.chapters.append(Chapter(name))
        return self

    def get(self, idx: int) -> object:
        if 0 <= idx < len(self.chapters):
            return self.chapters[idx]
        else:
            raise IndexError("Index out of range")

    @classmethod
    def create(cls):
        return cls()

class Chapter:
    def __init__(self, name: str):
        self.name = name

    def get_name(self) -> str:
        return self.name


class Result(enum.Enum):
    FINISHED = 1
    ROLLBACK = 2
    CRASHED = 3
```

Please note that Python does not have a direct equivalent to Java's `enum` class. Instead, we use the built-in `enum` module in Python.