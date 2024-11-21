Here is the equivalent Python code:

```Python
class PathException(Exception):
    def __init__(self, message="Timeseries is null", error_code=TSStatusCode.PATH_ERROR.value):
        super().__init__(message)
        self.error_code = error_code


# Define TSStatusCode as a dictionary for simplicity
TSStatusCode = {
    "PATH_ERROR": 1,
}

PathException()
PathException("Custom Message")
PathException("Another Custom Message", TSStatusCode["PATH_ERROR"])
```

Note that Python does not have an equivalent to Java's `serialVersionUID`. Also, the error codes are defined as a dictionary for simplicity.