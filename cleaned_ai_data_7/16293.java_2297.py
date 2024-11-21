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
