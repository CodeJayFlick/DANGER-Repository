Here is the translation of the Java code into Python:

```Python
class UnsignedInteger6DataType:
    def __init__(self):
        self.data_type_manager = None

    @staticmethod
    def data_type():
        return UnsignedInteger6DataType()

    def get_description(self):
        return "Unsigned 6-Byte Integer"

    def get_length(self):
        return 6

    def get_opposite_signedness_data_type(self):
        from ghidra.program.model.data import Integer6DataType
        return Integer6DataType().clone(self.get_data_type_manager())

    def clone(self, data_type_manager=None):
        if data_type_manager == self.get_data_type_manager():
            return self
        else:
            return UnsignedInteger6DataType(data_type_manager)
```

Please note that this Python code is not exactly equivalent to the Java code. The main differences are:

1. In Python, we don't need a `public` keyword for methods and variables.
2. We use `self` as the first argument in instance methods (like `__init__`, `get_description`, etc.) instead of using `this`.
3. There is no equivalent to Java's `@Override` annotation in Python.
4. The concept of static variables does not exist exactly like it does in Java, but we can achieve similar functionality by defining a class method (`data_type`) that returns an instance of the class.

Also note that this code assumes you have imported the necessary modules and classes from the `ghidra` package.