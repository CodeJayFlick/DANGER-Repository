Here's your Java exception class translated into a Python equivalent:

```Python
class ZooProviderNotFoundException(Exception):
    def __init__(self, message=""):
        if not message:
            message = "Zoo provider not found"
        super().__init__(message)
```

In this translation, we've kept the same structure and functionality as your Java class. The `__init__` method is used to initialize a new exception with an optional detail message. If no message is provided when creating a new instance of the exception, it defaults to "Zoo provider not found".