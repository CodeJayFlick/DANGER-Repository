class TimeValuePair:
    def __init__(self, timestamp: int, value):
        self.timestamp = timestamp
        self.value = value

    @property
    def get_timestamp(self) -> int:
        return self.timestamp

    @get_timestamp.setter
    def set_timestamp(self, timestamp: int) -> None:
        self.timestamp = timestamp

    @property
    def get_value(self):
        return self.value

    @get_value.setter
    def set_value(self, value):
        self.value = value

    def __str__(self) -> str:
        return f"{self.timestamp} : {self.get_value}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TimeValuePair):
            return (other.get_timestamp == self.timestamp and
                    other.get_value is not None and
                    other.get_value == self.value)
        return False

    def __hash__(self) -> int:
        return hash((self.timestamp, self.value))

    @property
    def get_size(self) -> int:
        if isinstance(self.value, str):
            size = 8 + len(self.value.encode('utf-8'))
        else:
            size = 8 + 8 + self.value.get_size()
        return size

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, TimeValuePair):
            raise TypeError("Comparision only possible with another TimeValuePair")
        return self.timestamp < other.timestamp
