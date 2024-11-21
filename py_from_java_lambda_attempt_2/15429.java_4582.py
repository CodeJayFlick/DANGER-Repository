Here is the translation of the Java code to Python:
```
import numpy as np
from djl_python_ndarray import NDArray

class RandomHue:
    def __init__(self, hue):
        self.hue = hue

    def transform(self, array: NDArray) -> NDArray:
        return ndimage_utils.random_hue(array, self.hue)
```
Note that I've used the `djl_python_ndarray` module to represent the `NDArray` class from Java. You may need to install this package separately depending on your Python environment.

Also, I've assumed that there is a separate utility function called `ndimage_utils.random_hue` which performs the same operation as its Java counterpart. If such a function does not exist in your Python codebase, you will need to implement it accordingly.