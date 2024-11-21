Here is the translation of the given Java code into equivalent Python:

```Python
import numpy as np

class ConstantEmbedding:
    def __init__(self, embedding):
        self.embedding = embedding

    def forward(self, inputs, training=False):
        base = np.tile(self.embedding, tuple(inputs[0].shape) + self.embedding.shape)
        return [base]

    def get_output_shapes(self, input_shapes):
        return [tuple(np.concatenate((input_shape, self.embedding.shape))) for input_shape in input_shapes]

    def save_parameters(self):  # Nothing to save
        pass

    def load_parameters(self, manager, is):  # Nothing to load
        pass

    def unembed(self, index):
        return None

    def encode(self, input_):
        return bytearray()

    def decode(self, byte_array):
        return None

    def embed(self, item):
        return 0

    def embed(self, manager, items):
        base = np.tile(self.embedding, tuple(len(items)) + self.embedding.shape)
        return [base]

    def has_item(self, item):
        return True
```

Please note that Python does not have direct equivalent of Java's `NDArray`, `Shape` and other classes. The above code uses NumPy arrays to represent the embedding and shapes.