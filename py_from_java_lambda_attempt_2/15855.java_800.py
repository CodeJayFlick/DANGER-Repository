Here is the translation of the Java code to Python:

```Python
import unittest
from djl.basicdataset import Cifar10
from djl.nn import Blocks
from djl.repository import Repository
from djl.training import DefaultTrainingConfig, Trainer
from djl.translate import TranslateException

class TestCifar10(unittest.TestCase):

    def test_cifar10_local(self):
        config = DefaultTrainingConfig(loss='softmaxCrossEntropyLoss')

        try:
            model = Model('model')
            model.set_block(Blocks.identityBlock())
            batch_size = len(config.get_devices()) * 32
            repository = Repository('test', 'src/test/resources/mlrepo')
            cifar10 = Cifar10.builder() \
                .opt_manager(model.get_nd_manager()) \
                .opt_usage(Cifar10.Usage.TEST) \
                .opt_repository(repository) \
                .set_sampling(batch_size, True) \
                .build()

            with Trainer(model, config) as trainer:
                batch = next(trainer.iterate_dataset(cifar10))
                self.assertEqual(len(batch.data), 1)
                self.assertEqual(len(batch.labels), 1)
                batch.close()
        except Exception as e:
            raise TranslateException(str(e))

    def test_cifar10_remote(self):
        config = DefaultTrainingConfig(loss='softmaxCrossEntropyLoss')

        try:
            model = Model('model')
            model.set_block(Blocks.identityBlock())
            cifar10 = Cifar10.builder() \
                .opt_manager(model.get_nd_manager()) \
                .opt_usage(Cifar10.Usage.TEST) \
                .set_sampling(32, True) \
                .build()

            with Trainer(model, config) as trainer:
                batch = next(trainer.iterate_dataset(cifar10))
                self.assertEqual(len(batch.data), 1)
                self.assertEqual(len(batch.labels), 1)
                batch.close()
        except Exception as e:
            raise TranslateException(str(e))

if __name__ == '__main__':
    unittest.main()
```

Please note that the `Model`, `Blocks`, and other classes might need to be replaced with their Python equivalents, depending on your specific use case.