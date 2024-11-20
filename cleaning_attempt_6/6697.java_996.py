class SequenceMiningParams:
    def __init__(self, min_percentage: float, required_bits_of_check: int, use_binary: bool):
        self.min_percentage = min_percentage
        self.required_bits_of_check = required_bits_of_check
        self.use_binary = use_binary

    @property
    def min_percentage(self) -> float:
        return self._min_percentage

    @min_percentage.setter
    def min_percentage(self, value: float):
        if not isinstance(value, (int, float)):
            raise TypeError("Min percentage must be a number")
        self._min_percentage = value

    @property
    def required_bits_of_check(self) -> int:
        return self._required_bits_of_check

    @required_bits_of_check.setter
    def required_bits_of_check(self, value: int):
        if not isinstance(value, int):
            raise TypeError("Required bits of check must be an integer")
        self._required_bits_of_check = value

    @property
    def use_binary(self) -> bool:
        return self._use_binary

    @use_binary.setter
    def use_binary(self, value: bool):
        if not isinstance(value, bool):
            raise TypeError("Use binary must be a boolean")
        self._use_binary = value


# Example usage:

params = SequenceMiningParams(0.5, 10, True)
print(params.min_percentage)  # Output: 0.5
print(params.required_bits_of_check)  # Output: 10
print(params.use_binary)  # Output: True

