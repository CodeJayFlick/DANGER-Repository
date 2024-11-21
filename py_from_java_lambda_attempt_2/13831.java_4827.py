Here is the translation of the Java code to Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class CachingConstants:
    """Constant class for defining constants."""

    USER_ACCOUNT = "user_accounts"
    USER_ID = "userID"
    USER_NAME = "userName"
    ADD_INFO = "additionalInfo"

CachingConstants()  # Constructor
```

Note that Python does not have a direct equivalent to Java's `public final` and `private`. In Python, you can use the underscore prefix (`_`) to indicate that an attribute is intended to be private. However, this is only a convention and does not provide any actual access control.

Also note that in Python, classes are defined using the `class` keyword followed by the class name. The constructor (or initializer) for a class is typically defined inside the class definition using the `__init__()` method.