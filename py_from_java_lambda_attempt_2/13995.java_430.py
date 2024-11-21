Here is the equivalent Python code:

```Python
class DataMapperException(Exception):
    def __init__(self, message: str):
        super().__init__(message)
```

Note that in Python, we don't need a `serialVersionUID` as it's not necessary for serialization or deserialization. Also, since Python doesn't have an equivalent to Java's checked exceptions (i.e., runtime exceptions), the exception class is defined using the built-in `Exception` class.

The constructor (`__init__`) takes one argument: the message that will be used when raising this exception.