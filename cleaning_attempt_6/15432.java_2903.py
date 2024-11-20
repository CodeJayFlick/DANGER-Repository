import numpy as np

class ToTensor:
    def transform(self, array):
        return NDImageUtils.to_tensor(array)

# Note: This assumes that you have a separate function or class called NDImageUtils
# with a method to_tensor() that takes an NDArray-like object and returns a tensor.
