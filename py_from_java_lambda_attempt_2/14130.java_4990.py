Here is the translation of the Java code to Python:

```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class InvalidOperationException(Exception):
    """Type of Exception raised when the Operation being invoked is Invalid."""
    serialVersionUID = -6191545255213410803L

    def __init__(self, message: str):
        super().__init__(message)
```

Note that I've kept the same structure and naming conventions as the original Java code. In Python, we don't need to specify a package name or import statements for this specific class, since it's not being used elsewhere in the program. The `serialVersionUID` is also preserved, although its purpose may be different in Python than in Java (in Java, it's used for serialization and deserialization of objects).