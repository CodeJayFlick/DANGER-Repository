Here is the translation of the given Java code into Python:

```Python
class L2Loss:
    def __init__(self):
        self.name = "L2Loss"
        self.weight = 1/2

    def __call__(self, label, prediction):
        pred = prediction.singleton_or_throw()
        label_reshaped = label.singleton_or_throw().reshape(pred.shape)
        loss = (label_reshaped - pred) ** 2 * self.weight
        return loss.mean()

# Usage:
l2_loss = L2Loss()
labels = ...  # your labels here
predictions = ...  # your predictions here

loss_value = l2_loss(labels, predictions)

print(loss_value)
```

Please note that this Python code is not a direct translation of the given Java code. The `singletonOrThrow()` and `reshape()` methods are specific to NDArray in Java but do not have direct equivalents in Python's NumPy library.