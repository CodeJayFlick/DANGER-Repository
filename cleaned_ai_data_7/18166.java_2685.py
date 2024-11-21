class StatisticsClassException(Exception):
    def __init__(self, className1: type, className2: type) -> None:
        message = f"Statistics classes mismatched: {className1.__name__} vs. {className2.__name__}"
        super().__init__(message)

    def __init__(self, message: str) -> None:
        super().__init__(message)
