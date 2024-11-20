Here is the translation of the given Java code into Python:

```Python
import numpy as np

class XavierInitializer:
    def __init__(self, random_type='uniform', factor_type='avg', magnitude=6):
        self.random_type = random_type
        self.factor_type = factor_type
        self.magnitude = magnitude

    @staticmethod
    def uniform(shape, dtype):
        return np.random.uniform(-1.0, 1.0, shape).astype(dtype)

    @staticmethod
    def gaussian(shape, dtype):
        return np.random.normal(0, 1.0, shape).astype(dtype)

    def initialize(self, manager, shape, dtype):
        if len(shape) < 2:
            raise ValueError("XavierInitializer cannot be applied to Shape with dimension: {}".format(len(shape)))

        hw_scale = 1
        fan_in = np.prod(shape[1:])
        fan_out = np.prod(shape[:1])
        factor = None

        if self.factor_type == 'avg':
            factor = (fan_in + fan_out) / 2.0
        elif self.factor_type in ['in', 'out']:
            factor = fan_in if self.factor_type == 'in' else fan_out
        else:
            raise ValueError("Invalid factor type, valid types are: avg, in, out")

        if factor == 0:
            raise RuntimeError("Xavier initializer factor is 0, please check your input shape.")

        scale = np.sqrt(self.magnitude / factor)

        if self.random_type == 'uniform':
            return XavierInitializer.uniform(shape, dtype)
        elif self.random_type == 'gaussian':
            return XavierInitializer.gaussian(shape, dtype)
        else:
            raise ValueError("Invalid randomType")
```

This Python code defines a class `XavierInitializer` that performs the same function as the Java original. It uses NumPy for numerical operations and raises exceptions when necessary to ensure correct usage of the initializer.