import numpy as np

class MissingOps:
    def __init__(self):
        pass

    @staticmethod
    def gather_nd(lookup: np.ndarray, indices: np.ndarray) -> np.ndarray:
        return np.take(lookup, indices)
