import numpy as np

class Normalize:
    def __init__(self, mean: list[float], std: list[float]):
        self.mean = mean
        self.std = std

    def transform(self, array: np.ndarray) -> np.ndarray:
        return NDImageUtils.normalize(array, self.mean, self.std)
