class PointCollector:
    def __init__(self):
        pass

    def put_int(self, timestamp: int, value: int) -> None:
        raise NotImplementedError("Method not implemented")

    def put_long(self, timestamp: int, value: int) -> None:
        self.put_int(timestamp, value)

    def put_float(self, timestamp: int, value: float) -> None:
        if isinstance(value, int):
            self.put_int(timestamp, value)
        else:
            raise ValueError("Float values are not supported")

    def put_double(self, timestamp: int, value: float) -> None:
        if isinstance(value, (int, float)):
            self.put_float(timestamp, value)
        else:
            raise ValueError("Double values must be a number")

    def put_boolean(self, timestamp: int, value: bool) -> None:
        pass

    def put_binary(self, timestamp: int, value: bytes) -> None:
        if isinstance(value, str):
            self.put_string(timestamp, value)
        elif not isinstance(value, (bytes)):
            raise ValueError("Binary values must be a string or bytes")

    def put_string(self, timestamp: int, value: str) -> None:
        pass
