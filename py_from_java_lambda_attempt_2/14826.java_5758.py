Here is the translation of the Java code to Python:

```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class BusinessException(Exception):
    """The top-most type in our exception hierarchy that signifies that an unexpected error condition occurred.
       Its use is reserved as a "catch-all" for cases where no other subtype captures the specificity of the error
       condition in question. Calling code is not expected to be able to handle this error and should be reported to the maintainers immediately."""
    serialVersionUID = 6235833142062144336

    def __init__(self, message):
        """Ctor.
           @param message the error message"""
        super().__init__(message)
```

Note that Python does not have a direct equivalent of Java's `package` statement. Also, Python uses indentation to denote block-level structure, so I've removed the comments and reformatted the code accordingly.