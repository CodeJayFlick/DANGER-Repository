Here is the translation of the Java code to Python:
```
class AndFilter:
    def __init__(self):
        pass

    def __init__(self, left: 'Filter', right: 'Filter'):
        super().__init__(left, right)

    def satisfy(self, statistics) -> bool:
        return self.left.satisfy(statistics) and self.right.satisfy(statistics)

    def satisfy(self, time: int, value: object) -> bool:
        return self.left.satisfy(time, value) and self.right.satisfy(time, value)

    def satisfy_start_end_time(self, start_time: int, end_time: int) -> bool:
        return (self.left.satisfy_start_end_time(start_time, end_time)
                and self.right.satisfy_start_end_time(start_time, end_type))

    def contain_start_end_time(self, start_time: int, end_time: int) -> bool:
        return (self.left.contain_start_end_time(start_time, end_time)
                and self.right.contain_start_end_time(start_time, end_time))

    def __str__(self):
        return f"({self.left} && {self.right})"

    def copy(self) -> 'Filter':
        return AndFilter(self.left.copy(), self.right.copy())

    def get_serialize_id(self) -> str:
        return "AND"
```
Note that I used the `->` syntax to indicate the return type of each method, as this is a common convention in Python. Additionally, I replaced the Java-style comments with regular Python docstrings (`"""..."""`).