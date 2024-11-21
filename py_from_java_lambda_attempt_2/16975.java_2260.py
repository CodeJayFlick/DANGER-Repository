Here is the translation of the Java code to Python:
```
class NaivePathSelector:
    def __init__(self, paths: list, max_series_num: int):
        self.paths = paths
        self.max_series_num = max_series_num
        self.idx = 0

    def has_next(self) -> bool:
        return self.idx < len(self(paths))

    def next(self) -> list:
        if not self.has_next():
            raise NoSuchElementException()
        ret = self.paths[self.idx:self.idx + self.max_series_num]
        self.idx += self.max_series_num
        return ret

class NoSuchElementException(Exception):
    pass
```
Note that I've used Python's type hints to indicate the types of variables and function parameters, but this is not strictly necessary for the code to work.