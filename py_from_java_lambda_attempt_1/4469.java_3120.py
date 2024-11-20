Here is the translation of the Java code to Python:
```
class ExceptionHandlerFrameException(Exception):
    def __init__(self, message=None, cause=None):
        if message is None and cause is None:
            super().__init__()
        elif message is not None and cause is None:
            super().__init__(message)
        elif message is None and cause is not None:
            super().__init__(cause)
        else:
            super().__init__(message, cause)

    def __str__(self):
        return self.args[0] if len(self.args) > 0 else "ExceptionHandlerFrameException"
```
Note that in Python, we don't need to specify the `serialVersionUID` as it is not a concept in Python. Also, the constructor (`__init__`) method takes two optional arguments: `message` and `cause`. The behavior of the constructor depends on whether one or both of these arguments are provided.

The rest of the code remains similar to Java, with the exception that we don't need to specify getters and setters for attributes.