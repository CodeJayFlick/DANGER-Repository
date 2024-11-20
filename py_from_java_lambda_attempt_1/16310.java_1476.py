Here's your Java code translated into equivalent Python:

```Python
import platform
import mxnet as mx
from djl import testing

class TestUtils:
    @staticmethod
    def is_windows():
        return platform.system().startswith("Windows")

    @staticmethod
    def is_mxnet():
        engine_name = mx.engine.get_engine_name()
        return "MXNet" == engine_name

    @staticmethod
    def is_engine(name):
        engine_name = mx.engine.get_engine_name()
        return name == engine_name

    @staticmethod
    def verify_nd_array_values(array, expected_shape, sum_value, mean_value, max_value, min_value):
        if array.isnan().any():
            raise ValueError("There are NaNs in this array")
        
        testing.assert_equals(array.shape(), expected_shape)
        testing.assert_almost_equal(array.sum().asnumpy()[0], sum_value)
        testing.assert_almost_equal(array.mean().asnumpy()[0], mean_value)
        testing.assert_almost_equal(array.max().asnumpy()[0], max_value)
        testing.assert_almost_equal(array.min().asnumpy()[0], min_value)

    @staticmethod
    def get_devices():
        if not mx.engine.has_capability(mx.capabilities.CUDNN) and TestUtils.is_mxnet():
            return [mx.cpu()]
        
        return mx.engine.get_devices(1)
```

Note that I've used the `djl` library for some of the functionality, as it seems to be a Python port of the DL4J (Deep Learning 4 Java) library.