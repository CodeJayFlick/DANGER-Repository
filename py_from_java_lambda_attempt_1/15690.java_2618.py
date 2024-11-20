Here is the translation of the given Java code into Python:

```Python
class L1Loss:
    def __init__(self):
        self.name = "L1Loss"
        self.weight = 1

    def __call__(self, label, prediction):
        pred = prediction.singleton_or_throw()
        label_reshaped = label.singleton_or_throw().reshape(pred.shape)
        loss = (label_reshaped - pred).abs()
        
        if self.weight != 1:
            # avoid broadcast mul
            loss *= self.weight
        
        return loss.mean()

# Usage example:
l1_loss = L1Loss()
labels = ...  # your labels here
predictions = ...  # your predictions here

loss_value = l1_loss(labels, predictions)
```

Please note that Python does not have direct equivalent of Java's package and import statements. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass; however, this concept doesn't exist in Python as it uses inheritance differently.

In addition, Python's NumPy library (`numpy`) provides functions for array operations similar to those provided by Java's NDArray and NDList.