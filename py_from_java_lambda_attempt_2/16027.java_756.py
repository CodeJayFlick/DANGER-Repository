Here is a translation of the Java code into equivalent Python:

```Python
import torch
from typing import List, Tuple

class PtSymbolBlock:
    def __init__(self):
        self.manager = None
        self.handle = None
        self.uid = None
        self.is_train = True
        self.first = True
        self.input_descriptions = []
        self.output_descriptions = []

    def forward(self, *inputs) -> torch.Tensor:
        return IValueUtils.forward(self, inputs)

    def close(self):
        if self.handle is not None:
            JniUtils.delete_module(self.handle)
            self.manager.detach_internal(self.uid)
            self.manager = None
            self.handle = None

class PtNDManager:
    @staticmethod
    def new_base_manager():
        return torch.device("cpu")

def IValueUtils.forward(block, inputs):
    # implement this function to forward the input values through the block
    pass

# Usage example:

block = PtSymbolBlock()
manager = PtNDManager.new_base_manager()

# Set up your model here...

inputs = [torch.tensor([1.0]), torch.tensor([2.0])]
output = block.forward(*inputs)
```

Please note that this is a simplified translation and does not include all the details from the original Java code, such as error handling, logging, etc.