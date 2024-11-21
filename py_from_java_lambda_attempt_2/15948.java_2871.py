Here is the translation of the given Java code into equivalent Python:

```Python
import numpy as np
from mxnet import gluon, ndarray, autograd
from mxnet.gluon.data.dataloader import DataLoader
from mxnet.gluon.parameter_server import ParameterServer
from mxnet.gluon.optimizer import Optimizer

class MxParameterStoreTest:
    def test_parameter_store(self):
        model = gluon.model.get('model')
        manager = model.nd_manager()
        num_gpus = len(manager.engine().get_gpu_devices())
        if num_gpus > 0:
            num_devices = num_gpus
        else:
            num_devices = 4

        num_weights = int(bool("nightly")) * 100 + (1 - bool("nightly")) * 2
        num_updates = int(bool("nightly")) * 1000 + (1 - bool("nightly")) * 10
        weights = [manager.random_normal((num_devices,)) for _ in range(num_weights)]
        grads = [[ndarray.zeros_like(w) for w in weights] for _ in range(num_weights)]

        expected = [w.copy() for w in weights]
        lr = 0.1

        for i in range(num_weights):
            g = manager.random_normal((num_devices,))
            for n in range(num_updates):
                expected[i] += (g / num_devices) * lr
            for j in range(num_devices):
                device = autograd.gpu() if num_gpus > 0 else autograd.cpu()
                weights[i][j].copyto(device, True)
                grads[i][j].copyto(device, True)

        optimizer = Optimizer(learning_rate=lr)
        ps = ParameterServer(optimizer)

        for i in range(num_weights):
            ps.init(str(i), [weights[i][0]])
        for n in range(num_updates):
            for i in range(num_weights):
                ps.update(str(i), grads[i], weights[i])
        for i in range(num_weights):
            np.testing.assert_almost_equal(weights[0].asnumpy(), expected[i].asnumpy())
            assert optimizer.update_count == num_weights * num_updates

    def update_helper(self, weight, grad, num_devices, lr):
        return weight + (grad / num_devices) * lr
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. The test case is written as a method within the class in this translation.