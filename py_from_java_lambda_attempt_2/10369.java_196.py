Here is the translation of the Java interface `Array` into a Python class:

```python
class Array:
    def __init__(self):
        self.data = []

    def remove(self, index: int) -> None:
        if 0 <= index < len(self.data):
            self.data[index] = 0

    def get_last_non_empty_index(self) -> int:
        for i in range(len(self.data)):
            if self.data[i]:
                return i
        return -1

    def copy_data_to(self, index: int, table: list, to_index: int, to_col: int) -> None:
        if 0 <= index < len(self.data):
            table[to_index][to_col] = self.data[index]
```

Note that I've used Python's built-in `list` type as the underlying data structure for this class. The methods have been translated from Java to Python, with some minor changes:

* In Python, we don't need explicit getters and setters like in Java.
* We use a more concise syntax for defining methods (e.g., `def remove(self, index: int) -> None:` instead of `public void remove(int index);`).
* The `remove` method sets the value at the given index to 0 if it exists. If not, it does nothing.
* The `get_last_non_empty_index` method returns -1 if no non-empty elements are found in the array.

This Python class is equivalent to the original Java interface `Array`.