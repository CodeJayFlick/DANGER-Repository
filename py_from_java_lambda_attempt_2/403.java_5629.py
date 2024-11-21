Here is the translation of the Java code to Python:
```
class DebugExceptionFilterInformation:
    def __init__(self, n_params: int, parameters: list):
        self.n_params = n_params
        self.parameters = parameters

    @property
    def number_of_parameters(self) -> int:
        return self.n_params

    def get_parameter(self, param_number: int) -> dict:
        return self.parameters[param_number]

    def get_parameters(self) -> list:
        return self.parameters


# Example usage:
parameters = [
    {"key1": "value1", "key2": "value2"},
    {"key3": "value3", "key4": "value4"}
]
filter_info = DebugExceptionFilterInformation(2, parameters)

print(filter_info.number_of_parameters)  # Output: 2
print(filter_info.get_parameter(0))  # Output: {'key1': 'value1', 'key2': 'value2'}
print(filter_info.get_parameters())  # Output: [{'key1': 'value1', 'key2': 'value2'}, {'key3': 'value3', 'key4': 'value4'}]
```
Note that I used Python's built-in `list` type to represent the array of parameters, and a dictionary (`dict`) to represent each parameter. The Java code uses an inner class `DEBUG_EXCEPTION_FILTER_PARAMETERS`, which is not directly translatable to Python; instead, I chose to use dictionaries as a simple representation of the parameter data.