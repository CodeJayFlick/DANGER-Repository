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
