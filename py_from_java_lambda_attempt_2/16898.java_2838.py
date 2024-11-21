Here is the translation of the Java code to Python:
```
class AuthException(Exception):
    def __init__(self, message=""):
        super().__init__(message)

    def __init__(self, message="", cause=None):
        if cause is None:
            super().__init__(message)
        else:
            super().__init__(message, cause)

    def __init__(self, cause):
        super().__init__(cause)
```
Note that in Python, we don't need to specify the `serialVersionUID` as it's not a concept in Python. Also, the constructor (`__init__`) is used instead of a separate method for initialization.

Also, I've kept the same exception hierarchy and naming convention as the original Java code.