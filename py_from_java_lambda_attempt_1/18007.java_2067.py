Here is the equivalent Python code:

```Python
import random
import string

class RandomNum:
    def __init__(self):
        pass  # Utility class, no initialization needed

    @staticmethod
    def get_random_long(min_value: int, max_value: int) -> int:
        return min(int(random.random() * (max_value - min_value + 1)), max_value)

    @staticmethod
    def get_random_int(min_value: int, max_value: int) -> int:
        return random.randint(min_value, max_value)

    @staticmethod
    def get_random_float(min_value: float, max_value: float) -> float:
        return min(max(random.random() * (max_value - min_value), min_value), max_value)

    @staticmethod
    def get_abnormal_data(frequency: int) -> int:
        return random.randint(0, frequency)

    @staticmethod
    def get_random_text(length: int) -> str:
        base = string.ascii_lowercase + string.digits
        return ''.join(random.choice(base) for _ in range(length))
```

Note that Python's `random` module does not have a direct equivalent to Java's `Random.nextLong()` or `Random.nextInt()`, so I used the `random.random()` function, which returns a random floating point number between 0 and 1. For integer values, you can use the `randint()` function from the same module.

Also note that Python does not have an equivalent to Java's `StringBuilder` class; instead, we use string concatenation or list comprehension with `''.join()`.