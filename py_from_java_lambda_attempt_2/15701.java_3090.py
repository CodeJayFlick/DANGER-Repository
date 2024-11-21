Here is the translation of the given Java code into equivalent Python:

```Python
import numpy as np

class Adadelta:
    def __init__(self):
        self.rho = 0.9
        self.epsilon = 1e-8
        self.accumG = {}
        self.accumDelta = {}

    class Builder:
        def __init__(self):
            pass

        @property
        def rho(self):
            return self._rho

        @rho.setter
        def rho(self, value):
            self._rho = value

        @property
        def epsilon(self):
            return self._epsilon

        @epsilon.setter
        def epsilon(self, value):
            self._epsilon = value

        def build(self):
            adadelta = Adadelta()
            adadelta.rho = self.rho
            adadelta.epsilon = self.epsilon
            return adadelta


class Optimizer:
    pass


def update(parameter_id, weight, grad, optimizer):
    weight_decay = 0.01
    inputs = [weight, grad]
    
    if parameter_id not in optimizer.accumG:
        optimizer.accumG[parameter_id] = np.zeros_like(weight)
    if parameter_id not in optimizer.accumDelta:
        optimizer.accumDelta[parameter_id] = np.zeros_like(weight)

    accum_g = optimizer.accumG[parameter_id]
    accum_delta = optimizer.accumDelta[parameter_id]

    inputs.append(accum_g)
    inputs.append(accum_delta)

    weights = [weight, ]

    ex = weight
    adadelta_update(inputs, weights, weight_decay)


def adadelta_update(inputs, weights, weight_decay):
    # implement the actual Adadelta update rule here


# Example usage:
optimizer = Adadelta().Builder()
optimizer.rho = 0.9
optimizer.epsilon = 1e-8

weight = np.random.rand(10)
grad = np.random.rand(10)

update("parameter_id", weight, grad, optimizer.build())
```

Please note that the actual implementation of `adadelta_update` function is missing in this translation as it was not provided in the original Java code.