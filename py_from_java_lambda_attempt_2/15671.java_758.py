Here is the translation of the given Java code into equivalent Python:

```Python
import numpy as np

class NormalInitializer:
    def __init__(self, sigma=0.01):
        self.sigma = sigma

    @property
    def sigma(self):
        return self._sigma

    @sigma.setter
    def sigma(self, value):
        if not isinstance(value, (int, float)):
            raise TypeError('Sigma must be a number')
        self._sigma = value

    def initialize(self, shape):
        return np.random.normal(0.0, self.sigma, size=shape)
```

This Python code defines a class `NormalInitializer` that can be used to generate random numbers from a normal distribution with mean 0 and standard deviation specified by the user (default is 0.01). The `initialize` method generates an array of such random values for given shape.

Note: In this translation, I have assumed that you want to use NumPy's random number generator (`np.random.normal`) which returns a floating point value from the normal distribution with mean and standard deviation specified by the user.