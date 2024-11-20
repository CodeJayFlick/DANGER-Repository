import numpy as np

class ConstantInitializer:
    def __init__(self, value):
        self.value = value

    def initialize(self, shape, dtype):
        return np.full(shape, self.value, dtype)
