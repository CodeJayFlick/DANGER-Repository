Here is the translation of the Java code to Python:
```
import sqlite3

class IoTDBSQLException(Exception):
    def __init__(self, reason):
        super().__init__(reason)

    def __init__(self, reason, status_code):
        super().__init__(f"{reason} (status code: {status_code})")

    def __init__(self, cause):
        super().__init__(str(cause))
```
Note that in Python, we don't need to specify a `serialVersionUID` as it is not used. Also, the equivalent of Java's `SQLException` class is Python's built-in `Exception` class.

The constructor (`__init__`) methods are similar to their Java counterparts, but with some minor differences:

* In Python, you can pass multiple arguments to the constructor using keyword arguments (e.g., `reason`, `status_code`). This allows for more flexibility in how the exception is initialized.
* The `super().__init__(...)` call initializes the parent class (`Exception`) with the given argument(s).
* The `f-string` formatting used in the second constructor method is a Python 3.6+ feature that allows you to embed expressions inside string literals.

This code defines an `IoTDBSQLException` class that inherits from Python's built-in `Exception` class, and provides three constructors for initializing exceptions with different types of arguments: a reason message, a status code, or a cause exception object.