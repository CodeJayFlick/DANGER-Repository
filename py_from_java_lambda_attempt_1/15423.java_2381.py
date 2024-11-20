Here is the translation of the given Java code into Python:

```Python
import numpy as np

class Normalize:
    def __init__(self, mean: list[float], std: list[float]):
        self.mean = mean
        self.std = std

    def transform(self, array: np.ndarray) -> np.ndarray:
        return NDImageUtils.normalize(array, self.mean, self.std)
```

Note that the Python code does not include any imports for `NDArray` or `NDImageUtils`, as these are likely custom classes in your Java code.