Here is the translation of the Java code to Python:
```
import numpy as np
from typing import List

class ActionSpace(List):
    def __init__(self):
        super().__init__()

    def random_action(self) -> list:
        return [np.random.choice(list(self)) for _ in range(len(self))]
```
Note that I've used the `numpy` library to generate a random choice from each element of the list, and converted the result to a Python list. The rest of the code is straightforward translation from Java to Python.

Also, please note that this code assumes you have installed the necessary libraries (e.g., NumPy) before running it.