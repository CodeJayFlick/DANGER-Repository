Here is the translation of the Java code to Python:
```
class Location:
    INTERNALLY_DEFINED = Location("<internally defined>", 1)

    def __init__(self, filename: str, lineno: int):
        self.filename = filename
        self.lineno = lineno

    def __str__(self) -> str:
        return f"{self.filename}:{self.lineno}"
```
Note that I've used the `f` string notation to create a formatted string in the `__str__` method, which is equivalent to concatenating strings with `+`.