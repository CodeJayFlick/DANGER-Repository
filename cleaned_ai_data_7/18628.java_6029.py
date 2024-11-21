class MapResponseModel:
    def __init__(self):
        self.values = {}

    def add_value(self, key: str, value: str) -> None:
        self.values[key] = value

    def get_values(self) -> dict:
        return self.values.copy()

    def set_values(self, values: dict) -> None:
        self.values = values
