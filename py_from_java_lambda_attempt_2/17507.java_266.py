Here's the equivalent Python code:

```Python
class UDFInputSeriesDataTypeNotValidException(Exception):
    def __init__(self, index: int, expected: str, actual: TSDataType) -> None:
        super().__init__(f"The data type of the input series (index: {index}) is not valid. Expected: {expected}. Actual: {actual}")

class UDFInputSeriesDataTypeNotValidExceptionMulti(Exception):
    def __init__(self, index: int, expected: str, actual: TSDataType) -> None:
        super().__init__(f"The data type of the input series (index: {index}) is not valid. Expected: {expected}. Actual: {actual}")

TSDataType = 'ts_data_type'  # Assuming this is an enum in Java
```

Note that Python does not have a direct equivalent to Java's `enum` types, so I've replaced it with the string `'ts_data_type'`. Also, Python has built-in support for exceptions and you don't need to extend any base class like `Exception` or `UDFParameterNotValidException` in this case.