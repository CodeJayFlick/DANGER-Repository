import json
from typing import List

class SingleValueModel:
    def __init__(self):
        self.value = None

    def set_value(self, value: str) -> None:
        self.value = value

    def get_value(self) -> str:
        return self.value


class MapResponseModel:
    def __init__(self):
        self.values = {}

    def add_value(self, key: str, value: str) -> None:
        self.values[key] = value

    def to_dict(self) -> dict:
        return self.values


class EchoJerseyResource:

    @path("/echo")
    def echo_decoded_param(self, param: str):
        model = SingleValueModel()
        model.set_value(param)
        return {"value": model.get_value()}

    @path("/filter-attribute")
    def return_filter_attribute(self) -> dict:
        # implementation
        pass

    @path("/list-query-string")
    def echo_query_string_length(self, param: List[str]) -> dict:
        model = SingleValueModel()
        model.set_value(str(len(param)))
        return {"value": model.get_value()}

    @path("/encoded-param")
    def echo_encoded_param(self, param: str) -> dict:
        model = SingleValueModel()
        model.set_value(param)
        return {"value": model.get_value()}

    # ... other methods

if __name__ == "__main__":
    app = EchoJerseyResource()

