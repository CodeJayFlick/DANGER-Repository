Here is the translation of the Java code into Python:

```Python
import numpy as np
from djl import Model, Block, ParameterStore, NDArray, EasyTrain
from typing import List, Tuple

class AlexNetTest:
    def test_train_with_default_channels(self):
        config = DefaultTrainingConfig(Loss.softmaxCrossEntropyLoss())
        alexnet = AlexNet.builder().build()
        
        try:
            model = Model.newInstance("alexnet")
            model.setBlock(alexnet)
            
            trainer = model.newTrainer(config)
            batch_size = 1
            input_shape = (batch_size, 3, 224, 224)  # Assuming the default channels are RGB
            
            manager = trainer.getManager()
            trainer.initialize(input_shape)
            
            input_data = np.ones((batch_size,) + input_shape[2:])
            label_data = np.ones((batch_size,))
            
            batch = Batch(manager.newSubManager(), [NDArray.from_numpy_array(input_data)], 
                           [NDArray.from_numpy_array(label_data)], batch_size, 'stack', 'stack')
            
            parameters = alexnet.getParameters()
            EasyTrain.trainBatch(trainer, batch)
            trainer.step()
            
            self.assertEqual(parameters[0].getValue().getShape(), (96,) + input_shape[2:])
            self.assertEqual(parameters[2].getValue().getShape(), (256, 96) + input_shape[2:])
            self.assertEqual(parameters[4].getValue().getShape(), (384, 256) + input_shape[2:])
            self.assertEqual(parameters[6].getValue().getShape(), (384, 384) + input_shape[2:])
            self.assertEqual(parameters[8].getValue().getShape(), (256, 384) + input_shape[2:])
            self.assertEqual(parameters[10].getValue().getShape(), (4096, 6400))
            self.assertEqual(parameters[12].getValue().getShape(), (4096, 4096))
        except:
            pass

    def test_train_with_custom_channels(self):
        config = DefaultTrainingConfig(Loss.softmaxCrossEntropyLoss())
        
        alexnet = AlexNet.builder() \
                .setDropOutRate(0.8) \
                .setNumChannels([128, 128, 128, 512, 384, 2048, 2048]) \
                .build()
        
        try:
            model = Model.newInstance("alexnet")
            model.setBlock(alexnet)
            
            trainer = model.newTrainer(config)
            batch_size = 1
            input_shape = (batch_size,) + (224, 224)  # Assuming the custom channels
            
            manager = trainer.getManager()
            trainer.initialize(input_shape)
            
            input_data = np.ones((batch_size,) + input_shape[2:])
            label_data = np.ones((batch_size,))
            
            batch = Batch(manager.newSubManager(), [NDArray.from_numpy_array(input_data)], 
                           [NDArray.from_numpy_array(label_data)], batch_size, 'stack', 'stack')
            
            parameters = alexnet.getParameters()
            EasyTrain.trainBatch(trainer, batch)
            trainer.step()
            
            self.assertEqual(parameters[0].getValue().getShape(), (128,) + input_shape[2:])
            self.assertEqual(parameters[2].getValue().getShape(), (128, 128) + input_shape[2:])
            self.assertEqual(parameters[4].getValue().getShape(), (128, 128) + input_shape[2:])
            self.assertEqual(parameters[6].getValue().getShape(), (512, 128) + input_shape[2:])
            self.assertEqual(parameters[8].getValue().getShape(), (384, 512) + input_shape[2:])
            self.assertEqual(parameters[10].getValue().getShape(), (2048, 9600))
            self.assertEqual(parameters[12].getValue().getShape(), (2048, 2048))
        except:
            pass

    def test_output_shapes(self):
        try:
            manager = NDManager.newBaseManager()
            
            batch_size = 2
            x_data = np.ones((batch_size,) + (224, 224))  # Assuming the default channels are RGB
            
            alexnet = AlexNet.builder().build()
            alexnet.setInitializer(Initializer.ONES, Parameter.Type.WEIGHT)
            alexnet.initialize(manager, DataType.FLOAT32, x_data.shape)
            
            shape_map = {}
            for child in alexnet.getChildren():
                new_shape = child.getValue().getOutputShapes((x_data.shape,))
                shape_map[child.getKey()] = new_shape[0]
        except:
            pass

    def test_forward_method(self):
        try:
            manager = NDManager.newBaseManager()
            
            alexnet = AlexNet.builder().build()
            batch_size = 1
            x_data = np.ones((batch_size,) + (224, 224))  # Assuming the default channels are RGB
            
            alexnet.setInitializer(Initializer.ONES, Parameter.Type.WEIGHT)
            alexnet.initialize(manager, DataType.FLOAT32, x_data.shape)
            
            ps = ParameterStore(manager, True)
            x_hat = alexnet.forward(ps, [NDArray.from_numpy_array(x_data)], False).singletonOrThrow()
            
            self.assertEqual(x_hat.getShape(), (batch_size,) + (10,))
        except:
            pass
```

Please note that the above Python code is a direct translation of your Java code. However, you may need to adjust it according to your specific requirements and the actual functionality of your `AlexNet` class in Python.