Here is the translation of the Java code to Python:
```
class OrFilter:
    def __init__(self):
        pass

    def __init__(self, left: 'Filter', right: 'Filter'):
        super().__init__(left, right)

    def __str__(self) -> str:
        return f"({self.left} || {self.right})"

    def copy(self) -> 'OrFilter':
        return OrFilter(self.left.copy(), self.right.copy())

    def satisfy_statistics(self, statistics: dict) -> bool:
        return self.left.satisfy(statistics) or self.right.satisfy(statistics)

    def satisfy_time_value(self, time: int, value: object) -> bool:
        return self.left.satisfy(time, value) or self.right.satisfy(time, value)

    def satisfy_start_end_time(self, start_time: int, end_time: int) -> bool:
        return self.left.satisfy(start_time, end_time) or self.right.satisfy(start_time, end_time)

    def contain_start_end_time(self, start_time: int, end_time: int) -> bool:
        return self.left.contain_start_end_time(start_time, end_time) or self.right.contain_start_end_time(start_time, end_time)

    @property
    def serialize_id(self):
        return 'OR'
```
Note that I've used Python's type hints to indicate the types of the `left` and `right` attributes. In Python, these are not enforced at runtime, but they can be useful for documentation and static analysis purposes.

I've also replaced Java's `long` type with Python's built-in integer type (`int`).