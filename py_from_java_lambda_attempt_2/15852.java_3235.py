Here is the translation of the Java code into equivalent Python code:

```Python
import numpy as np
from djl.basicdataset import AmesRandomAccess
from djl.translate.TranslateException import TranslateException
from djl.training.TrainingConfig import TrainingConfig
from djl.nn.blocks import Blocks
from djl.nn.parameter import Parameter

class AmesRandomAccessTest:
    def test_ames_random_access_remote(self):
        try:
            config = TrainingConfig(loss='softmaxCrossEntropyLoss')
            model = Model('model', blocks=Blocks.identityBlock())

            ames_random_access = AmesRandomAccess()
            ames_random_access.add_feature("MiscVal")
            ames_random_access.add_feature("id")
            ames_random_access.add_feature("alley", categorical=True)
            ames_random_access.set_sampling(32, True)

            ames_random_access.prepare()

            size = len(ames_random_access)
            assert size == 1460

            record = ames_random_access.get(0)
            data = np.array(record.data).flatten()
            labels = [record.label]
            assert np.allclose(data, [0, 1, 1, 0, 0])
            assert labels[0] == 208500.0

        except (IOException, TranslateException):
            raise
```

Please note that the Python code is not an exact translation of the Java code as some parts may be missing or modified to fit into a more natural and idiomatic Python style.