Here is the equivalent Python code:

```Python
import math

class UDTFConstPi:
    def before_start(self):
        pass  # No need for this in Python

    def transform(self, row: dict) -> float:
        return math.pi


# Example usage:
udtf = UDTFConstPi()
print(udtf.transform({'time': 'some_time'}))  # Output: 3.14159265359
```

Note that the `before_start` method is not needed in Python, as there's no equivalent concept to Java's "before start" method. The `transform` method takes a dictionary representing a row and returns the transformed value (in this case, math.PI).