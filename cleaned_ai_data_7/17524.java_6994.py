import math

class UDTFConstPi:
    def before_start(self):
        pass  # No need for this in Python

    def transform(self, row: dict) -> float:
        return math.pi


# Example usage:
udtf = UDTFConstPi()
print(udtf.transform({'time': 'some_time'}))  # Output: 3.14159265359
