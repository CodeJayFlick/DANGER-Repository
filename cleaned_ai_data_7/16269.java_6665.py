import unittest
from ai_djl import Application, MalformedModelException, Model, BasicModelZoo, AlexNet, Criteria, Block, Trainer, DefaultTrainingConfig, SoftmaxCrossEntropyLoss
from ai_djl.modality import Classifications, Image, DetectedObjects
from ai_djl.ndarray.types import Shape

class ImperativeModelZooTest(unittest.TestCase):

    def test_imperative_model_input_output(self):
        if not TestUtils.is_mxnet():
            raise unittest.SkipTest("Resnet50-cifar10 model only available in MXNet")

        criteria = Criteria.builder() \
                         .opt_application(Application.CV.IMAGE_CLASSIFICATION) \
                         .set_types(Image, Classifications) \
                         .opt_group_id(BasicModelZoo.GROUP_ID) \
                         .build()
        
        try:
            model = criteria.load_model()
            self.assertEqual(model.describe_input().values[0], Shape(1, 3, 32, 32))
            self.assertEqual(model.describe_output().values[0], Shape(1, 10))

        except (MalformedModelException, ModelNotFoundException):
            pass

        ssd_criteria = Criteria.builder() \
                         .opt_application(Application.CV.OBJECT_DETECTION) \
                         .set_types(Image, DetectedObjects) \
                         .build()
        
        try:
            model = ssd_criteria.load_model()
            self.assertEqual(model.describe_input().values[0], Shape(32, 3, 256, 256))
            self.assertEqual(model.describe_output().values[0], Shape(1, 5444, 4))
            self.assertEqual(model.describe_output().values[1], Shape(32, 5444, 2))
            self.assertEqual(model.describe_output().values[2], Shape(32, 21776))

        except (MalformedModelException, ModelNotFoundException):
            pass

        alex_net = AlexNet.builder().build()
        
        try:
            model = Model.newInstance("alexnet")
            model.set_block(alex_net)
            
            trainer = model.new_trainer(DefaultTrainingConfig(SoftmaxCrossEntropyLoss()))
            input_shape = Shape(32, 3, 224, 224)
            trainer.initialize(input_shape)

            self.assertEqual(model.describe_input().values[0], Shape(32, 3, 224, 224))
            self.assertEqual(model.describe_output().values[0], Shape(32, 10))

        except (MalformedModelException, ModelNotFoundException):
            pass

if __name__ == '__main__':
    unittest.main()
