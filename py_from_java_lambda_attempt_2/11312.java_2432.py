Here is the translation of the Java code to Python:
```
class GTaskResultInfo:
    def __init__(self, result):
        self.result = result

    def get_result(self):
        return self.result

    def __str__(self):
        if self.result is None:
            return "---- New Transaction ------"
        else:
            return str(self.result)
```
Note that I've used the `__init__` method to initialize the object, and the `get_result` method to retrieve the wrapped result. The `__str__` method is equivalent to Java's `toString()` method, which returns a string representation of the object.

Also, in Python, we don't need to explicitly define getters and setters like we do in Java. Instead, we can access the attributes directly using dot notation (e.g., `obj.result`).