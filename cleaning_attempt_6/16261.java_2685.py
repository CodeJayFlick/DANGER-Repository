import numpy as np
from djl.basic import Model, Block, ParameterStore
from djl.engine import Engine
from djl.translate import Batchifier
from org.testng.annotations import Test

class GoogLeNetTest:
    @Test
    def test_train_with_default_channels(self):
        config = DefaultTrainingConfig(Loss.softmaxCrossEntropyLoss())
        goog_le_net = Block(GoogLeNet.builder().build())

        try:
            model = Model("googlenet")
            model.set_block(goog_le_net)
            trainer = model.new_trainer(config)

            batch_size = 1
            input_shape = (batch_size, 96, 96)
            manager = trainer.get_manager()
            trainer.initialize(input_shape)

            input_array = np.ones((input_shape[0],) + tuple(input_shape[1:]))
            label_array = np.ones((batch_size,))
            batch = Batch(manager.new_sub_manager(), [manager.tensor_from_numpy(input_array)], 
                           [manager.tensor_from_numpy(label_array)], batch_size, Batchifier.STACK, 0)

            parameters = goog_le_net.get_parameters()
            EasyTrain.train_batch(trainer, batch)
            trainer.step()

            self.assertEqual(parameters[0].get_value().numpy().shape, (64,) + tuple((7, 7)))
            self.assertEqual(parameters[18].get_value().numpy().shape, (128, 256) + tuple((1, 1)))
            self.assertEqual(parameters[34].get_value().numpy().shape, (208, 96) + tuple((3, 3)))
            self.assertEqual(parameters[60].get_value().numpy().shape, (24, 512) + tuple((1, 1)))
            self.assertEqual(parameters[78].get_value().numpy().shape, (256, 528) + tuple((1, 1)))
            self.assertEqual(parameters[100].get_value().numpy().shape, (128, 832) + tuple((1, 1)))
            self.assertEqual(parameters[114].get_value().numpy().shape, (10, 1024))

        except Exception as e:
            print(f"An error occurred: {e}")

    @Test
    def test_output_shapes(self):
        try:
            manager = NDManager.new_base_manager()
            batch_size = 1
            x_array = np.ones((batch_size,) + tuple((96, 96)))
            current_shape = (batch_size,) + tuple(x_array.shape[1:])

            goog_le_net = Block(GoogLeNet.builder().build())
            goog_le_net.set_initializer(Initializer.ONES, Parameter.Type.WEIGHT)
            goog_le_net.initialize(manager, DataType.FLOAT32, current_shape)

            shape_map = {}
            for i in range(len(goog_le_net.get_children())):
                new_shapes = goog_le_net.get_children()[i].get_output_shapes([current_shape])
                current_shape = new_shapes[0]
                shape_map[goog_le_net.get_children()[i].key] = current_shape

            self.assertEqual(shape_map["01SequentialBlock"], (batch_size, 64) + tuple((24, 24)))
            self.assertEqual(shape_map["02SequentialBlock"], (batch_size, 192) + tuple((12, 12)))
            self.assertEqual(shape_map["03SequentialBlock"], (batch_size, 480) + tuple((6, 6)))
            self.assertEqual(shape_map["04SequentialBlock"], (batch_size, 832) + tuple((3, 3)))
            self.assertEqual(shape_map["05SequentialBlock"], (batch_size, 1024))

        except Exception as e:
            print(f"An error occurred: {e}")

    @Test
    def test_forward_method(self):
        try:
            manager = NDManager.new_base_manager()
            goog_le_net = Block(GoogLeNet.builder().build())
            batch_size = 1
            x_array = np.ones((batch_size,) + tuple((28, 28)))
            goog_le_net.set_initializer(Initializer.ONES, Parameter.Type.WEIGHT)
            goog_le_net.initialize(manager, DataType.FLOAT32, (batch_size,) + tuple(x_array.shape[1:]))

            ps = ParameterStore(manager, True)
            x_hat = goog_le_net.forward(ps, [manager.tensor_from_numpy(x_array)], True).singleton_or_throw()

            self.assertEqual(x_hat.numpy().shape, (batch_size, 10))

        except Exception as e:
            print(f"An error occurred: {e}")
