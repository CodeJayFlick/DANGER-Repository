import numpy as np
from typing import Dict, Any

class Adagrad:
    def __init__(self):
        self.learning_rate_tracker = None
        self.epsilon = 1e-8
        self.history: Dict[str, Dict[Any, np.ndarray]] = {}

    @property
    def learning_rate(self) -> float:
        return self._learning_rate

    @learning_rate.setter
    def learning_rate(self, value):
        if not isinstance(value, (int, float)):
            raise ValueError("Learning rate must be a number")
        self._learning_rate = value

    @property
    def epsilon_(self) -> float:
        return self.epsilon_

    @epsilon_.setter
    def epsilon_(self, value: Any):
        if not isinstance(value, (int, float)):
            raise ValueError("Epsilon must be a number")
        self.epsilon_ = value

    def update(self, parameter_id: str, weight: np.ndarray, grad: np.ndarray) -> None:
        t = self.update_count(parameter_id)
        new_learning_rate = self.learning_rate_tracker.get_new_value(t)
        weight_decay = self.weight_decay()

        if not isinstance(new_learning_rate, (int, float)) or \
           not isinstance(weight_decay, (int, float)):
            raise ValueError("Learning rate and/or weight decay is NaN or infinite")

        inputs = [weight, grad.to_sparse(), np.zeros_like(weight)]
        weights = [weight]

        # TODO: change to our own implementation
        adagrad_update(inputs, weights, new_learning_rate, weight_decay)

    @staticmethod
    def builder() -> 'Builder':
        return Adagrad.Builder()

class Builder:
    def __init__(self):
        self.learning_rate_tracker = Tracker(fixed=0.001)
        self.epsilon_ = 1e-8

    def opt_learning_rate_tracker(self, learning_rate_tracker: Any) -> 'Builder':
        self.learning_rate_tracker = learning_rate_tracker
        return self

    def opt_epsilon_(self, epsilon_: float) -> 'Builder':
        self.epsilon_ = epsilon_
        return self

    def build(self) -> Adagrad:
        return Adagrad()
