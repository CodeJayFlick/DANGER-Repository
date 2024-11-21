Here is the translation of the Java code to Python:
```
import logging

class FunctionOperator:
    def __init__(self, filter_type):
        self.filter_type = filter_type

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def reverse_func(self):
        # Implemented by subclass
        pass

    def add_child_operator(self, op):
        self.logger.error("Cannot add child to leaf FilterOperator, now it's FunctionOperator")
        return False


if __name__ == "__main__":
    filter_type = "some_filter_type"
    function_operator = FunctionOperator(filter_type)
    # Use the `function_operator` object
```
Note that I've used Python's built-in logging module instead of SLF4J, and created a property for the logger to make it easier to access. The rest of the code is straightforward translation from Java to Python.