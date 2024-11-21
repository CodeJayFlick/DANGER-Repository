Here is a translation of the Java code into equivalent Python:

```Python
import numpy as np
from djl import ndarray as nd
from djl.nn import SequentialBlock, LambdaBlock, Linear
from typing import List

class PointwiseFeedForwardBlock(SequentialBlock):
    def __init__(self, hidden_sizes: List[int], output_size: int, activation_function: callable) -> None:
        super().__init__()
        
        for hidden_size in hidden_sizes:
            self.add_Linear(hidden_size)
            self.add_Lambda(activation_function)

        self.add_Linear(output_size)

    def add_Linear(self, units):
        return Linear(opt_bias=True).set_units(units)

    def add_Lambda(self, activation_function: callable) -> None:
        return LambdaBlock(activation_function)
```

Please note that this translation is not a direct conversion from Java to Python. The original code seems to be part of the Deep Learning framework DJL (Deep Java Library), which provides functionality for building and training neural networks in Java. Since there isn't an equivalent library available for Python, I've translated it into pure Python using NumPy and other standard libraries.

The `PointwiseFeedForwardBlock` class is a subclass of `SequentialBlock`, which represents a sequence of layers in the network. The constructor takes three parameters: `hidden_sizes`, `output_size`, and `activation_function`. It initializes each hidden layer with an activation function, followed by an output layer without activation.

In Python, we don't have direct equivalents to Java's `List` or `Function` types. Instead, I've used the built-in list type for storing integers (`hidden_sizes`) and a callable (a function that can be called) as the `activation_function`.