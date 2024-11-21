Here is the translation of the Java code to Python:
```
class BatchExecutionException(Exception):
    def __init__(self, message=None, status_list=None):
        super().__init__()
        self.status_list = status_list
        if message:
            self.message = message

    @property
    def status_list(self):
        return self._status_list

    @status_list.setter
    def status_list(self, value):
        self._status_list = value
```
Note that I've used Python's built-in `Exception` class as the base class for our custom exception. This is equivalent to Java's `extends StatementExecutionException`.

I've also removed the unnecessary imports and package declarations, as they are not relevant in a Python context.

The constructor (`__init__`) takes two optional arguments: `message` (a string) and `status_list` (a list of `TSStatus` objects). If either argument is provided, it sets the corresponding attribute on the exception instance. The `super().__init__()` call initializes the base class with any message that was passed in.

The `@property` decorator allows us to define a read-only property (`status_list`) that returns the value of our internal `_status_list` attribute. We also define a setter for this property, which updates the internal attribute when called.

That's it! Let me know if you have any questions or need further clarification.