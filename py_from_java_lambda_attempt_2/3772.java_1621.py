Here is the translation of the Java code to Python:
```
class DataWindowContext:
    def __init__(self, provider, data_table):
        pass  # equivalent to super(provider, data_table)

    def get_data_table(self):
        return self.get_context_object()

def get_context_object():
    raise NotImplementedError("This method must be implemented")
```
Note that I had to introduce a new function `get_context_object()` in the Python translation because there is no direct equivalent of Java's `getContextObject()` method. In Python, you would typically implement this as an abstract method (using the `abc` module) or raise a `NotImplementedError`.