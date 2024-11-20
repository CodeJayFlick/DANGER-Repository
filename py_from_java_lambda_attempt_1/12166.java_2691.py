Here is the translation of the Java code to Python:
```
class KeyRange:
    def __init__(self, min_key: int, max_key: int):
        self.min_key = min_key
        self.max_key = max_key

    def contains(self, key: int) -> bool:
        return min_key <= key <= max_key

    def length(self) -> int:
        return (max_key - min_key + 1)
```
Note that I've kept the same variable names and method signatures as in the original Java code. However, Python is a dynamically-typed language, so you don't need to specify types for variables or function parameters like you do in Java.

Also, note that I've used the `__init__` special method to initialize the object's attributes, which is equivalent to the constructor in Java.