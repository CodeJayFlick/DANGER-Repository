Here is the equivalent Python code:

```
class RPCServiceException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, e):
        super().__init__(f"{message} {e}")
```