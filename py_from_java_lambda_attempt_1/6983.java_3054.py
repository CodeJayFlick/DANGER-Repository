Here is the equivalent Python code:

```Python
class FunctionCallData:
    def __init__(self, address_of_call: 'Address', call_function_name: str, format_string: str):
        self.address_of_call = address_of_call
        self.call_function_name = call_function_name
        self.format_string = format_string

    @property
    def address_of_call(self) -> 'Address':
        return self._address_of_call

    @address_of_call.setter
    def address_of_call(self, value: 'Address'):
        self._address_of_call = value

    @property
    def call_function_name(self) -> str:
        return self._call_function_name

    @call_function_name.setter
    def call_function_name(self, value: str):
        self._call_function_name = value

    @property
    def format_string(self) -> str:
        return self._format_string

    @format_string.setter
    def format_string(self, value: str):
        self._format_string = value


class Address:
    pass  # You would need to implement the Address class in Python
```

Note that I've used type hints for clarity and readability. Also, since there is no direct equivalent of Java's `Address` class in Python, I left it as a placeholder (`pass`).