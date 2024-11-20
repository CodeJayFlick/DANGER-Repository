Here is the translation of the given Java code into equivalent Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class RemoteServiceException(Exception):
    """ Exception thrown when `RemoteService` does not respond successfully. """
    
    def __init__(self, message: str):
        super().__init__(message)
```

Note that Python's exception handling is similar to Java's but with some differences in syntax and functionality.