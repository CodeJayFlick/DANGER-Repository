Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ai_djl import SingleShotDetection
from ai_djl.ndarray import NDManager, Shape, DataType
from ai_djl.nn import Block, SequentialBlock
from typing import List

class TestSingleShotDetection(unittest.TestCase):

    def test_class_predictor_blocks(self):
        block = SingleShotDetection.get_class_prediction_block(5, 10)
        self.assertEqual(block.output_shapes([Shape(2, 8, 20, 20)])[0], Shape(2, 55, 20, 20))
        block = SingleShotDetection.get_class_prediction_block(3, 10)
        self.assertEqual(block.output_shapes([Shape(2, 16, 10, 10)])[0], Shape(2, 33, 10, 10))

    def test_anchor_predictor_blocks(self):
        block = SingleShotDetection.get_anchor_prediction_block(5)
        self.assertEqual(block.output_shapes([Shape(2, 8, 20, 20)])[0], Shape(2, 20, 20, 20))
        block = SingleShotDetection.get_class_prediction_block(3, 10)
        self.assertEqual(block.output_shapes([Shape(2, 16, 10, 10)])[0], Shape(2, 33, 10, 10))

    def test_down_sampling_block(self):
        sequential_block = SingleShotDetection.get_down_sampling_block(10)
        self.assertEqual(sequential_block.output_shapes([Shape(2, 3, 20, 20)])[0], Shape(2, 10, 10, 10))

    def test_single_shot_detection_shape(self):
        with NDManager() as manager:
            num_filters = [16, 32, 64]
            block = SequentialBlock()
            for num_filter in num_filters:
                block.add(SingleShotDetection.get_down_sampling_block(num_filter))
            
            sizes = []
            ratios = [[] for _ in range(5)]
            for i in range(5):
                ratios[i] = [1.0, 2.0, 0.5]
            sizes.append([0.2, 0.272])
            sizes.append([0.37, 0.447])
            sizes.append([0.54, 0.619])
            sizes.append([0.71, 0.79])
            sizes.append([0.88, 0.961])

            ssd = SingleShotDetection.builder() \
                .set_num_classes(1) \
                .set_num_features(3) \
                .opt_global_pool(True) \
                .set_ratios(ratios) \
                .set_sizes(sizes) \
                .set_base_network(block) \
                .build()
            ssd.initialize(manager, DataType.FLOAT32, Shape(32, 3, 256, 256))
            parameter_store = ParameterStore(manager, False)
            output = ssd.forward(parameter_store, [manager.ones(Shape(32, 3, 256, 256))], False)
            self.assertEqual(output[0].shape, Shape(1, 5444, 4))
            self.assertEqual(output[1].shape, Shape(32, 5444, 2))
            self.assertEqual(output[2].shape, Shape(32, 21776))

            output_shapes = ssd.output_shapes([Shape(32, 3, 256, 256)])
            self.assertEqual(output_shapes[0], Shape(1, 5444, 4))
            self.assertEqual(output_shapes[1], Shape(32, 5444, 2))
            self.assertEqual(output_shapes[2], Shape(32, 21776))

if __name__ == '__main__':
    unittest.main()
```