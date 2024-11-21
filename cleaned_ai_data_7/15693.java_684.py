import numpy as np

class L2WeightDecay:
    def __init__(self, name="L2WeightDecay", parameters=None, lambda_=1):
        self.name = name
        if isinstance(parameters, list) and all(isinstance(param, np.ndarray) for param in parameters):
            self.parameters = parameters
        else:
            raise ValueError("parameters must be a list of numpy arrays")
        self.lambda_ = lambda_

    def l2(self, w: np.ndarray) -> float:
        return (w ** 2).sum()

    def evaluate(self, label=None, prediction=None) -> float:
        if not isinstance(label, list):
            raise ValueError("label must be a list of numpy arrays")
        if not isinstance(prediction, list):
            raise ValueError("prediction must be a list of numpy arrays")

        sum_ = 0.0
        for w in self.parameters:
            sum_ += self.l2(w)
        return sum_ * self.lambda_
