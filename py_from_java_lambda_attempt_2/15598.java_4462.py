Here is the translation of the Java code to Python:
```
import numpy as np

class MissingOps:
    def __init__(self):
        pass

    @staticmethod
    def gather_nd(lookup: np.ndarray, indices: np.ndarray) -> np.ndarray:
        return np.take(lookup, indices)
```
Note that I've used the NumPy library (`numpy` or `np`) to perform the equivalent operations. Specifically:

* The `gatherNd` method is translated to a static method in Python.
* The `NDArray` class from Java becomes a simple NumPy array (`np.ndarray`) in Python.
* The `getManager().invoke("gather_nd", ...)` call is replaced with the NumPy function `np.take`, which performs the equivalent gather operation.

This code should work as expected, assuming you have the necessary dependencies installed (e.g., NumPy).