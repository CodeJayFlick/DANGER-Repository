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
