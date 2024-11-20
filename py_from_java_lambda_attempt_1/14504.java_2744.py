Here is the translation of the given Java code into Python:

```Python
class Result:
    def __init__(self, data):
        self.data = data


class ArrayResult(Result):
    def __init__(self, data: list[list[int]]):
        super().__init__(data)
```

Note that in this translation, I've kept the same structure and naming conventions as the original Java code. However, Python does not have a direct equivalent to Java's `package` statement or copyright notice at the top of the file.