Here is the translation of the Java code to Python:
```
class Utils:
    def __init__(self):
        raise ValueError("Utility class")

    @staticmethod
    def convert_string_to_integer(device: str) -> int:
        sum = 0
        for c in device:
            sum += ord(c)
        return sum

    @staticmethod
    def get_time_series(sql: str) -> str:
        return sql.split(',')[0].strip()
```
Note that I've used the `@staticmethod` decorator to define static methods, and the `ord()` function to convert characters to integers. The rest of the code is straightforward translation from Java to Python.

Also, in Python, we don't need a separate class for utility functions like this. We could have written these as standalone functions instead:
```
def convert_string_to_integer(device: str) -> int:
    sum = 0
    for c in device:
        sum += ord(c)
    return sum

def get_time_series(sql: str) -> str:
    return sql.split(',')[0].strip()
```