Here is the translation of the given Java code into equivalent Python:

```Python
class NDArrrayIndexPick:
    def __init__(self, indices):
        self.indices = indices

    @property
    def rank(self):
        return 1

    @property
    def get_indices(self):
        return self.indices


# Example usage:
import numpy as np

indices_array = np.array([0, 1])
pick_object = NDArrrayIndexPick(indices_array)

print(pick_object.rank)  # Output: 1
print(pick_object.get_indices)  # Output: [0, 1]
```

Note that Python does not have direct equivalent of Java's `package` statement. Also, the concept of private variables is different in Python as it uses encapsulation and access modifiers are used to control access to class attributes.