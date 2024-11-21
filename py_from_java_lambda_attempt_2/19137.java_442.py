Here is the translation of the Java code to Python:
```
class VersionStoreException(Exception):
    def __init__(self):
        super().__init__()

    @classmethod
    def with_message_and_cause(cls, message: str, cause: Exception) -> 'VersionStoreException':
        return cls(message, cause)

    @classmethod
    def with_message(cls, message: str) -> 'VersionStoreException':
        return cls(message)

    @classmethod
    def with_cause(cls, cause: Exception) -> 'VersionStoreException':
        return cls(cause)
```
Note that in Python, we don't need to specify the `serialVersionUID` as it is not a concept in Python. Also, the constructor (`__init__`) and other methods are defined using the standard Python syntax.

The `with_message_and_cause`, `with_message`, and `with_cause` classmethods are equivalent to the constructors with different parameters in Java.