Here is the translation of the Java code into Python:

```Python
import numpy as np
from djl.basicdataset import AirfoilRandomAccess
from djl.translate.TranslateException import TranslateException
from djl.training.TrainingConfig import TrainingConfig
from djl.training.Loss import Loss
from djl.testing.Assertion import assertEquals

class AirfoilRandomAccessTest:
    def test_airfoil_remote(self):
        config = TrainingConfig(loss=Loss.softmaxCrossEntropyLoss())
        
        try:
            model = Model("model")
            model.set_block(Blocks.identityBlock())

            airfoil = AirfoilRandomAccess.builder() \
                .opt_usage(Dataset.Usage.TRAIN) \
                .add_feature("chordlen") \
                .add_feature("freq") \
                .set_sampling(32, True) \
                .build()

            trainer = model.new_trainer(config)
            batch = next(trainer.iterate_dataset(airfoil))
            assertEquals(batch.data.size(), 1)
            assertEquals(batch.labels.size(), 1)
            batch.close()
        except (IOException, TranslateException):
            pass

    def test_airfoil_remote_preprocessing(self):
        airfoil = AirfoilRandomAccess.builder() \
            .opt_usage(Dataset.Usage.TRAIN) \
            .opt_normalize(True) \
            .opt_limit(1500) \
            .set_sampling(10, True) \
            .build()

        airfoil.prepare()
        
        record = airfoil.get(NDManager.new_base_manager(), 0)
        data = record.data
        labels = record.labels

        epsilon = 1e-4
        
        expected = [-0.6603, -1.1448, 1.797, 1.3109, -0.6443]
        assertEquals(data.head().to_float_array(), expected, epsilon)
        assertEquals(labels.head().to_float_array(), [0.1937], epsilon)

if __name__ == "__main__":
    test = AirfoilRandomAccessTest()
    test.test_airfoil_remote()
    test.test_airfoil_remote_preprocessing()
```

Please note that the code is translated from Java to Python, but it may not be a direct translation as some methods or classes might have different names in Python.