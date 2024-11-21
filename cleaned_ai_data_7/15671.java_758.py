import numpy as np

class NormalInitializer:
    def __init__(self, sigma=0.01):
        self.sigma = sigma

    @property
    def sigma(self):
        return self._sigma

    @sigma.setter
    def sigma(self, value):
        if not isinstance(value, (int, float)):
            raise TypeError('Sigma must be a number')
        self._sigma = value

    def initialize(self, shape):
        return np.random.normal(0.0, self.sigma, size=shape)
