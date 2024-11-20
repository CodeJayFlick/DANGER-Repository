Here is the translation of the Java code to Python:
```
class UnsupportedIndexTypeException(Exception):
    def __init__(self, index_type: str) -> None:
        super().__init__(f"Unsupported index type: {index_type}")
```
Note that I've used the built-in `Exception` class in Python as a base class for our custom exception. The constructor (`__init__`) takes an `index_type` parameter and uses it to create a message string, which is then passed to the parent class's constructor using the `super()` function.

Also note that there is no equivalent to Java's `serialVersionUID` in Python, as Python does not have a concept of versioning for classes.