class Linear:
    def __init__(self):
        self.units = None
        self.input_features = None
        self.input_shape = None
        self.weight = None
        self.bias = None

    @staticmethod
    def linear(input, weight, bias=None):
        if bias is not None:
            return input + (weight * bias).T
        else:
            return input.dot(weight)

    @classmethod
    def builder(cls):
        return LinearBuilder()

class LinearBuilder:
    def __init__(self):
        self.units = None
        self.bias = True

    def set_units(self, units):
        self.units = units
        return self

    def opt_bias(self, bias):
        self.bias = bias
        return self

    def build(self):
        if self.units is None:
            raise ValueError("You must specify the number of output channels")
        linear_block = Linear()
        linear_block.units = self.units
        if not self.bias:
            linear_block.bias = None
        else:
            linear_block.bias = np.zeros((self.units,))
        return linear_block

import numpy as np
