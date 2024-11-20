Here is the translation of the given Java code into Python:

```Python
class Adam:
    def __init__(self):
        self.learning_rate_tracker = 0.001
        self.beta1 = 0.9
        self.beta2 = 0.999
        self.epsilon = 1e-8

    def update(self, parameter_id: str, weight: float, grad: float) -> None:
        t = self.update_count(parameter_id)
        coef1 = (1 - self.beta1 ** t)
        coef2 = (1 - self.beta2 ** t)
        lr = self.learning_rate_tracker
        new_lr = lr * math.sqrt(coef2) / coef1

        if not isinstance(new_lr, float):
            raise ValueError("Learning rate is NaN or infinite")

        inputs = [weight, grad]
        weights = [weight]

        ex = weight.get_nd_array_internal()
        ex.adam_update(inputs, weights, new_lr, 0.0, True)

    def update_count(self, parameter_id: str) -> int:
        # implement this method
        pass

class Builder:
    def __init__(self):
        self.learning_rate_tracker = Tracker(0.001)
        self.beta1 = 0.9
        self.beta2 = 0.999
        self.epsilon = 1e-8

    @property
    def learning_rate_tracker(self) -> 'Tracker':
        return self._learning_rate_tracker

    @learning_rate_tracker.setter
    def learning_rate_tracker(self, value: float):
        self._learning_rate_tracker = Tracker(value)

    @property
    def beta1(self) -> float:
        return self._beta1

    @beta1.setter
    def beta1(self, value: float):
        self._beta1 = value

    @property
    def beta2(self) -> float:
        return self._beta2

    @beta2.setter
    def beta2(self, value: float):
        self._beta2 = value

    @property
    def epsilon(self) -> float:
        return self._epsilon

    @epsilon.setter
    def epsilon(self, value: float):
        self._epsilon = value

    def build(self) -> Adam:
        return Adam()

class Tracker:
    def __init__(self, initial_value: float):
        self.value = initial_value

    def get_new_value(self, t: int) -> float:
        # implement this method
        pass
```

Please note that the above Python code is a direct translation of your given Java code. However, it may not work as expected because some methods like `update_count`, `adam_update` and `get_new_value` are not implemented in the provided Java code. You will need to implement these methods according to your requirements.

Also, note that I have used Python's built-in `math` module for mathematical operations.