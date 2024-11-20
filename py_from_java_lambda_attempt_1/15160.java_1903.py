Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class BookDuplicateException(Exception):
    def __init__(self, message):
        super().__init__(message)
```
Note that in Python, we don't need a `package` declaration or any other Java-specific constructs. We simply define the exception class using the built-in `Exception` class and provide an initializer method (`__init__`) to set the error message.