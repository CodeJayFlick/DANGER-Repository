Here is the translation of the Java code to Python:
```
import numpy as np

class ConstantInitializer:
    def __init__(self, value):
        self.value = value

    def initialize(self, shape, dtype):
        return np.full(shape, self.value, dtype)
```
Note that I've removed the copyright and license information, as well as the Java-specific imports and annotations. The Python code is a direct translation of the original Java code.

Here's a brief explanation of the changes:

* In Python, we don't need to specify types for variables or method parameters.
* We use `__init__` instead of a constructor (`public class ConstantInitializer implements Initializer { ... }`) to define the initializer method.
* The `initialize` method takes three arguments: `shape`, `dtype`, and returns an NDArray (which is equivalent to Java's `NDArray`).