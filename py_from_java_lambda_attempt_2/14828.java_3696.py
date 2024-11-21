Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CustomerNotFoundException(Exception):
    """Indicates that the customer was not found.

    Severity of this error is bounded by its context: was the search for the customer triggered by an input from some end user, or were the search parameters pulled from your database?
    """

    def __init__(self, message):
        super().__init__(message)

# Example usage:
try:
    # code that might raise CustomerNotFoundException
except CustomerNotFoundException as e:
    print(f"Error: {e}")
```
Note that I've kept the same structure and naming conventions as the original Java code. In Python, we don't need to declare variables or methods ahead of time, so the `class` definition is more concise than in Java.

I also replaced the `extends BusinessException` part with simply inheriting from the built-in `Exception` class in Python.