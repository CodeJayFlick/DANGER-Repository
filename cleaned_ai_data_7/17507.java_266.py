class UDFInputSeriesDataTypeNotValidException(Exception):
    def __init__(self, index: int, expected: str, actual: TSDataType) -> None:
        super().__init__(f"The data type of the input series (index: {index}) is not valid. Expected: {expected}. Actual: {actual}")

class UDFInputSeriesDataTypeNotValidExceptionMulti(Exception):
    def __init__(self, index: int, expected: str, actual: TSDataType) -> None:
        super().__init__(f"The data type of the input series (index: {index}) is not valid. Expected: {expected}. Actual: {actual}")

TSDataType = 'ts_data_type'  # Assuming this is an enum in Java
