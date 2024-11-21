class UDFInputSeriesNumberNotValidException(Exception):
    def __init__(self, message=""):
        super().__init__(message)

    @classmethod
    def from_actual_expected(cls, actual: int, expected: int) -> 'UDFInputSeriesNumberNotValidException':
        return cls(f"the number of the input series is not valid. expected: {expected}. actual: {actual}.")

    @classmethod
    def from_actual_bounds(cls, actual: int, lower_bound: int, upper_bound: int) -> 'UDFInputSeriesNumberNotValidException':
        return cls(f"the number of the input series is not valid. expected: [{lower_bound}, {upper_bound)]. actual: {actual}.")
