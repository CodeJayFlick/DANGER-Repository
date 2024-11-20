Here is the translation of the Java code to Python:
```
class PartitionViolationException(Exception):
    def __init__(self, file):
        super().__init__(f"The data of file {file} cross partitions")
```
Note that I've used the built-in `Exception` class in Python as a base class for our custom exception. The constructor (`__init__`) takes a single argument `file`, which is passed to the superclass's constructor using the `super()` function.

The rest of the code remains similar, with the main difference being the use of f-strings (introduced in Python 3.6) instead of Java-style string formatting.