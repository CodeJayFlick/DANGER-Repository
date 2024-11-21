import numpy as np
from djl_python_ndarray import NDArray

class RandomHue:
    def __init__(self, hue):
        self.hue = hue

    def transform(self, array: NDArray) -> NDArray:
        return ndimage_utils.random_hue(array, self.hue)
