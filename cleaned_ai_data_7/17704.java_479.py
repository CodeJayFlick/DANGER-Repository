import enum

class TSDataType(enum.Enum):
    # Add your data types here (e.g., INT64, FLOAT32, etc.)
    pass

class Configuration:
    def __init__(self, data_type: TSDataType) -> None:
        self._data_type = data_type

    @property
    def data_type(self) -> TSDataType:
        return self._data_type

    def check(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
