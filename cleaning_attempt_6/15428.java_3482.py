import numpy as np
from djl.translate import Transform
from ai.djl.ndarray import NDArray

class RandomFlipTopBottom(Transform):
    def transform(self, array: NDArray) -> NDArray:
        return ndimage.random_flip_top_bottom(array)
