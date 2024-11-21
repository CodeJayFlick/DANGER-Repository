Here is the translation of the given Java code into Python:

```Python
import numpy as np

class SigmoidBinaryCrossEntropyLoss:
    def __init__(self, name="SigmoidBinaryCrossEntropyLoss", weight=1, from_sigmoid=False):
        self.name = name
        self.weight = weight
        self.from_sigmoid = from_sigmoid

    def evaluate(self, label, prediction):
        pred = np.array(prediction).reshape(-1)
        lab = np.array(label).reshape(-1)

        if not self.from_sigmoid:
            loss = (np.maximum(0, 1 - lab * pred) + np.log(np.exp(pred) + 1)).mean()
        else:
            eps = 1e-12
            loss = (-lab * np.log(np.clip(pred, eps, 1 - eps)) - (1 - lab) * np.log(np.clip(1 - pred, eps, 1 - eps))).sum()

        if self.weight != 1:
            loss *= self.weight

        return loss.mean()
```

Note that this Python code is not a direct translation of the Java code. The original Java code seems to be part of a larger system and uses specific classes (like `NDArray`, `Activation`) which are not available in standard Python. This Python code, on the other hand, uses NumPy arrays for numerical computations and does not require any additional libraries beyond NumPy itself.