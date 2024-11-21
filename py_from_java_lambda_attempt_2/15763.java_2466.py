Here is the equivalent Python code:

```Python
import random

class RandomUtils:
    def __init__(self):
        pass

    @staticmethod
    def random():
        return random.random()

    @staticmethod
    def next_gaussian():
        return random.gauss(0, 1)

    @staticmethod
    def randint(min_value=0, max_value=None):
        if max_value is None:
            return int(random.randint())
        else:
            return min(int(random.randint(max_value-min_value+1)), max_value-1) + min_value

    @staticmethod
    def uniform(lower=0.0, upper=1.0):
        return (upper - lower) * random.random() + lower

# Example usage:
print(RandomUtils.random())
print(RandomUtils.next_gaussian())
print(RandomUtils.randint(10, 20))
print(RandomUtils.uniform(5.0, 7.0))
```

Note that Python's `random` module does not have a direct equivalent to Java's `Random` class. The above code uses the built-in `random` module and provides some similar functionality through static methods in the `RandomUtils` class.

Also note that there is no exact equivalent of Java's `nextGaussian()` method, as Python's `random.gauss()` function does not return a double value with mean 0.0 and standard deviation 1.0 by default.