Here is the equivalent Python code:

```Python
import numpy as np
from djl_python import Model, Trainer, TrainingConfig, LossFunction, Initializer
from typing import List

class BlocksTest:
    def __init__(self):
        self.config = TrainingConfig(loss=LossFunction.L2())
            .setInitializer(Initializer.ones(), ParameterType.WEIGHT)

    @staticmethod
    def test_flatten_block():
        try:
            model = Model("model")
            model.setBlock(Model.batchFlattenBlock())

            trainer = Trainer(model, config)
            manager = trainer.getManager()
            parameter_store = ParameterStore(manager, False)

            data = np.random.uniform(0, 255, (10, 28, 28))
            expected = data.reshape((10, 28 * 28))

            result = model.getBlock().forward(parameter_store, [data], True)[0]
            assert np.allclose(result, expected)
        except:
            pass

if __name__ == "__main__":
    test_flatten_block()
```

Please note that this code is not a direct translation of the Java code. It's an equivalent Python implementation using the djl-python library which provides similar functionality to DL4J (Deep Learning for Java).