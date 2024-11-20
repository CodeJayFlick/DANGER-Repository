Here is the translation of the Java code into Python:

```Python
import torch.nn as nn
from torch import Tensor
import unittest
import numpy as np

class PoolingOperationsTest(unittest.TestCase):
    def test_max_pool_1d(self):
        model = nn.MaxPool1d(2)
        input_data = Tensor(np.ones((2, 2)))
        expected_output = Tensor(np.ones((2, 1)))
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_max_pool_2d(self):
        model = nn.MaxPool2d(2)
        input_data = Tensor(np.ones((2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1, 1)))
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_max_pool_3d(self):
        model = nn.MaxPool3d(2)
        input_data = Tensor(np.ones((2, 2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1, 1, 1)))
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_global_max_pool_1d(self):
        model = nn.AdaptiveMaxPool1d(1)
        input_data = Tensor(np.ones((2, 2)))
        expected_output = Tensor(np.ones((2, 1)))
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_global_max_pool_2d(self):
        model = nn.AdaptiveMaxPool2d((1, 1))
        input_data = Tensor(np.ones((2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1)))
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_global_max_pool_3d(self):
        model = nn.AdaptiveMaxPool3d((1, 1, 1))
        input_data = Tensor(np.ones((2, 2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1, 1)))
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_avg_pool_1d(self):
        model = nn.AvgPool1d(2)
        input_data = Tensor(np.ones((2, 2)))
        expected_output = Tensor(np.ones((2, 1)) * 1.5
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_avg_pool_2d(self):
        model = nn.AvgPool2d(2)
        input_data = Tensor(np.ones((2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1)) * 1.25
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_avg_pool_3d(self):
        model = nn.AvgPool3d(2)
        input_data = Tensor(np.ones((2, 2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1, 1)) * 1.125
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_global_avg_pool_1d(self):
        model = nn.AdaptiveAvgPool1d(1)
        input_data = Tensor(np.ones((2, 2)))
        expected_output = Tensor(np.ones((2, 1)) * 1.5
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_global_avg_pool_2d(self):
        model = nn.AdaptiveAvgPool2d((1, 1))
        input_data = Tensor(np.ones((2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1)) * 1.25
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_global_avg_pool_3d(self):
        model = nn.AdaptiveAvgPool3d((1, 1, 1))
        input_data = Tensor(np.ones((2, 2, 2, 2, 2)))
        expected_output = Tensor(np.ones((2, 1, 1, 1)) * 1.125
        output = model(input_data.unsqueeze(0).unsqueeze(-1))
        self.assertTrue(torch.allclose(output.squeeze(), expected_output))

    def test_lp_pool_1d(self):
        raise unittest.SkipTest("LP Pooling is not supported in PyTorch")

if __name__ == '__main__':
    unittest.main()
```

Please note that LP pooling (lpPool) and its variants are not implemented in the provided code.