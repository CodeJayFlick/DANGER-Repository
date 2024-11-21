Here is the translation of the Java code to Python:

```Python
class FileUtils:
    def get_local_file_byte(self, file_path: str, unit: int) -> float:
        import os
        f = os.path.join(file_path)
        return self.get_local_file_byte(f, unit)

    def get_local_file_byte(self, file: str, unit: int) -> float:
        bytes = os.path.getsize(file)
        if unit == 0:
            return bytes
        elif unit == 1:
            return bytes / (1024 ** 1)
        elif unit == 2:
            return bytes / (1024 ** 2)
        elif unit == 3:
            return bytes / (1024 ** 3)
        else:
            raise ValueError("Invalid unit")

    def transform_unit(self, value: float, unit: int) -> float:
        if unit == 0:
            return value
        elif unit == 1:
            return value * (1024 ** -1)
        elif unit == 2:
            return value * (1024 ** -2)
        elif unit == 3:
            return value * (1024 ** -3)
        else:
            raise ValueError("Invalid unit")

    def transform_unit_to_byte(self, value: float, unit: int) -> float:
        if unit == 0:
            return value
        elif unit == 1:
            return value * (1024 ** 1)
        elif unit == 2:
            return value * (1024 ** 2)
        elif unit == 3:
            return value * (1024 ** 3)
        else:
            raise ValueError("Invalid unit")

    def format(self, num: float, round: int) -> float:
        a = int(num * (10 ** round))
        return a / (10 ** round)

class UnitEnum:
    B = 0
    KB = 1
    MB = 2
    GB = 3
    TB = 4
    PB = 5
    EB = 6

file_utils = FileUtils()
```

Note that Python does not have an equivalent to Java's `enum` type. Instead, we define a class with static attributes as shown above.