Here is the translation of the Java code to Python:
```
import numpy as np

class Crop:
    def __init__(self, x: int, y: int, width: int, height: int):
        self.x = x
        self.y = y
        self.width = width
        self.height = height

    def transform(self, array: np.ndarray) -> np.ndarray:
        return NDImageUtils.crop(array, self.x, self.y, self.width, self.height)
```
Note that I've used the NumPy library (`numpy as np`) to represent arrays in Python. The `NDArray` class from Java is not directly equivalent to a Python array or NumPy array, so I've replaced it with a plain old Python function.

Also, since there's no direct equivalent of Java's `Transform` interface in Python, I've simply defined the `Crop` class as a regular Python class.