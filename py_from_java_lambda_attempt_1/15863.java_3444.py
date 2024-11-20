Here is the translation of the Java code to Python:

```Python
import unittest
from djl.basicdataset import Mnist
from djl.nn import Blocks
from djl.repository import Repository
from djl.translate import TranslateException
from djl.training import DefaultTrainingConfig, Trainer
from djl.dataset import Batch

class TestMnist(unittest.TestCase):

    def test_mnist_local(self):
        config = DefaultTrainingConfig(loss='softmaxCrossEntropyLoss')

        try:
            model = Model('model')
            model.set_block(Blocks.identityBlock())

            manager = model.get_nd_manager()
            repository = Repository('test', 'src/test/resources/mlrepo')
            mnist = Mnist.builder() \
                .opt_manager(manager) \
                .opt_usage(Dataset.Usage.TEST) \
                .opt_repository(repository) \
                .set_sampling(32, True) \
                .build()

            with Trainer(model, config) as trainer:
                batch = next(trainer.iterate_dataset(mnist))
                self.assertEqual(batch.data.size(), 1)
                self.assertEqual(batch.labels.size(), 1)
                batch.close()
        except Exception as e:
            raise TranslateException(str(e))

    def test_mnist_remote(self):
        config = DefaultTrainingConfig(loss='softmaxCrossEntropyLoss')

        try:
            model = Model('model')
            model.set_block(Blocks.identityBlock())

            manager = model.get_nd_manager()
            mnist = Mnist.builder() \
                .opt_manager(manager) \
                .opt_usage(Dataset.Usage.TEST) \
                .set_sampling(32, True) \
                .build()

            with Trainer(model, config) as trainer:
                batch = next(trainer.iterate_dataset(mnist))
                self.assertEqual(batch.data.size(), 1)
                self.assertEqual(batch.labels.size(), 1)
                batch.close()
        except Exception as e:
            raise TranslateException(str(e))

if __name__ == '__main__':
    unittest.main()
```

Note that this code assumes you have the `djl` library installed. If not, please install it using pip: `pip install djl`.