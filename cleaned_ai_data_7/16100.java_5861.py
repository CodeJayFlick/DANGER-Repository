import numpy as np

class TrtNDManagerTest:
    def test_nd_array(self):
        try:
            import tensorrt as trt
        except ImportError:
            raise SkipException("Your os configuration doesn't support TensorRT.")

        if not hasattr(trt, 'CudaDevice'):
            raise SkipException("TensorRT only supports GPU.")

        manager = trt.NDManager.create()
        zeros = manager.allocate((1, 2), dtype=np.float32)
        np.copyto(zeros, np.zeros_like(np.array([[0]])))
        self.assertTrue(np.allclose(zeros, [[0]]))

        ones = manager.allocate((1, 2), dtype=np.float32)
        np.copyto(ones, np.ones_like(np.array([[1]])))
        self.assertTrue(np.allclose(ones, [[1]]))

        array = manager.create(np.array([0., 1., 2., 3.]))
        expected = np.array([0., 1., 2., 3.])
        self.assertTrue(np.allclose(array, expected))
