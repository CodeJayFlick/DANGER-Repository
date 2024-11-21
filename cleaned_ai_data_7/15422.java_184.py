import numpy as np

class Crop:
    def __init__(self, x: int, y: int, width: int, height: int):
        self.x = x
        self.y = y
        self.width = width
        self.height = height

    def transform(self, array: np.ndarray) -> np.ndarray:
        return NDImageUtils.crop(array, self.x, self.y, self.width, self.height)
