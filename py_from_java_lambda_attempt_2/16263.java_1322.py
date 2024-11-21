Here is the translation of the Java code into Python:

```Python
import numpy as np
from djl.basic import NDArray, NDList, Block, ParameterStore
from djl.engine import Engine
from djl.nn import SequentialBlock
from djl.translate import Batchifier
from org.testng.annotations import Test

class NiNTest:
    @Test
    def test_train_with_default_channels(self):
        config = DefaultTrainingConfig(loss=Loss.softmaxCrossEntropyLoss())
        nin_block = NiN().builder().build()
        
        try:
            model = Model("nin")
            model.setBlock(nin_block)
            
            trainer = model.newTrainer(config)
            batch_size = 1
            input_shape = (batch_size, 224, 224, 3) 
            manager = trainer.getManager()
            trainer.initialize(input_shape)

            input_array = np.ones(input_shape).astype(np.float32)
            label_array = np.ones((batch_size, 10)).astype(np.float32)
            
            batch = Batch(manager.newSubManager(), NDList([input_array]), NDList([label_array]), 
                           batch_size, Batchifier.STACK, Batchifier.STACK, 0, 0)

            parameters = nin_block.getParameters()
            EasyTrain.trainBatch(trainer, batch)
            trainer.step()

            assert np.array_equal(parameters[0].getValue().getArray(), np.ones((96, 1, 11, 11)).astype(np.float32))
            assert np.array_equal(parameters[2].getValue().getArray(), np.ones((96, 96, 1, 1)).astype(np.float32))
            assert np.array_equal(parameters[10].getValue().getArray(), np.ones((256, 256, 1, 1)).astype(np.float32))
            assert np.array_equal(parameters[16].getValue().getArray(), np.ones((384, 384, 1, 1)).astype(np.float32))
            assert np.array_equal(parameters[18].getValue().getArray(), np.ones((10, 384, 3, 3)).astype(np.float32))

        except Exception as e:
            print(f"Error: {e}")

    @Test
    def test_train_with_custom_channels(self):
        config = DefaultTrainingConfig(loss=Loss.softmaxCrossEntropyLoss())
        nin_block = NiN().builder() \
                        .setDropOutRate(0.8) \
                        .setNumChannels([48, 128, 384, 10]) \
                        .build()
        
        try:
            model = Model("nin")
            model.setBlock(nin_block)
            
            trainer = model.newTrainer(config)
            batch_size = 1
            input_shape = (batch_size, 224, 224, 3) 
            manager = trainer.getManager()
            trainer.initialize(input_shape)

            input_array = np.ones(input_shape).astype(np.float32)
            label_array = np.ones((batch_size, 10)).astype(np.float32)
            
            batch = Batch(manager.newSubManager(), NDList([input_array]), NDList([label_array]), 
                           batch_size, Batchifier.STACK, Batchifier.STACK, 0, 0)

            parameters = nin_block.getParameters()
            EasyTrain.trainBatch(trainer, batch)
            trainer.step()

            assert np.array_equal(parameters[0].getValue().getArray(), np.ones((48, 1, 11, 11)).astype(np.float32))
            assert np.array_equal(parameters[2].getValue().getArray(), np.ones((48, 48, 1, 1)).astype(np.float32))
            assert np.array_equal(parameters[8].getValue().getArray(), np.ones((128, 128, 1, 1)).astype(np.float32))
            assert np.array_equal(parameters[16].getValue().getArray(), np.ones((384, 384, 1, 1)).astype(np.float32))
            assert np.array_equal(parameters[20].getValue().getArray(), np.ones((10, 10, 1, 1)).astype(np.float32))

        except Exception as e:
            print(f"Error: {e}")

    @Test
    def test_output_shapes(self):
        try:
            manager = NDManager.newBaseManager()
            
            batch_size = 1
            x_array = np.ones((batch_size, 224, 224, 3)).astype(np.float32)
            current_shape = (batch_size,) + tuple(x_array.shape[1:])
            
            nin_block = NiN().builder().build()
            nin_block.setInitializer(Initializer.ONES, Parameter.Type.WEIGHT)
            nin_block.initialize(manager, DataType.FLOAT32, current_shape)

            shape_map = {}
            for i in range(len(nin_block.getChildren())):
                new_shapes = nin_block.getChildren()[i].getValue().getOutputShapes([current_shape])
                current_shape = tuple(new_shapes[0][1:])
                shape_map[nin_block.getChildren()[i].getKey()] = current_shape

            assert shape_map.get("01SequentialBlock") == (batch_size, 96, 54, 54)
            assert shape_map.get("03SequentialBlock") == (batch_size, 256, 26, 26)
            assert shape_map.get("05SequentialBlock") == (batch_size, 384, 12, 12)
            assert shape_map.get("08SequentialBlock") == (batch_size, 10, 5, 5)

        except Exception as e:
            print(f"Error: {e}")

    @Test
    def test_forward_method(self):
        try:
            manager = NDManager.newBaseManager()
            
            nin_block = NiN().builder().build()
            batch_size = 1
            x_array = np.ones((batch_size, 224, 224, 3)).astype(np.float32)
            nin_block.setInitializer(Initializer.ONES, Parameter.Type.WEIGHT)
            nin_block.initialize(manager, DataType.FLOAT32, (batch_size,) + tuple(x_array.shape[1:]))

            ps = ParameterStore(manager, True)
            x_hat = nin_block.forward(ps, NDList([x_array]), False).singletonOrThrow()

            assert np.array_equal(x_hat.getArray(), np.ones((batch_size, 10)).astype(np.float32))
        except Exception as e:
            print(f"Error: {e}")
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific environment.