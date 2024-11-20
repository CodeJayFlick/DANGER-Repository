import numpy as np
from scipy.stats import truncnorm
import unittest

class TestNDArrayCreationOp(unittest.TestCase):

    def test_creation(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.create([0, 1, 2, 3], (2, 2))
            self.assertEqual(array1.to_float_array(), [0, 1, 2, 3])
            self.assertEqual(array1.shape, (2, 2))

            array2 = manager.create(-100)
            self.assertEqual(array2.get_float(), -100)

            array3 = manager.create([0], shape=(1, 0))
            self.assertEqual(array3.shape, (1, 0))
            self.assertEqual(len(array3.to_array()), 0)

            data = np.arange(0, 100).astype(np.float64)
            array4 = manager.create(data)
            expected = manager.arange(0, 100, dtype=np.float64)
            self.assertTrue(np.allclose(array4, expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_create_csr_matrix(self):
        try:
            manager = NDManager.new_base_manager()
            indices = [(0, 1), (2, 0)]
            values = [3.0, 4.0, 5.0]
            buf = np.array(values).astype(np.float32)
            array = manager.create_csr(buf, indices, shape=(3, 4))
            expected = manager.create([7., 8., 9.], (2, 4)).to_dense()
            self.assertTrue(array.is_sparse())
            self.assertTrue(np.allclose(array.to_dense(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_create_row_sparse_matrix(self):
        try:
            manager = NDManager.new_base_manager()
            indices = [0, 1, 3]
            buf = np.array([1., 2., 3., 4., 5., 6.]).astype(np.float32)
            array = manager.create_row_sparse(buf, shape=(3, 2), indices=indices, shape_out=(4, 2))
            expected = manager.create([1., 2., 3., 0], (4, 2)).to_dense()
            self.assertTrue(array.is_sparse())
            self.assertTrue(np.allclose(array.to_dense(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_create_coo_matrix(self):
        try:
            manager = NDManager.new_base_manager()
            indices = [[0, 1], [2, 0]]
            values = [3., 4., 5.]
            buf = np.array(values).astype(np.float32)
            array = manager.create_coo(buf, indices, shape=(2, 4))
            expected = manager.create([7., 8., 9.], (2, 4)).to_dense()
            self.assertTrue(array.is_sparse())
            self.assertEqual(array.to_dense(), expected)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_duplicate(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.create([0, 1, 2], shape=(3,))
            expected = np.array([0., 1., 2.])
            self.assertTrue(np.allclose(array1.to_array(), expected))

            array2 = manager.ones(shape=(5,))
            expected = np.ones((5,))
            self.assertTrue(np.allclose(array2.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_zeros(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.zeros(shape=(3,))
            expected = np.array([0., 0., 0.])
            self.assertTrue(np.allclose(array1.to_array(), expected))

            array2 = manager.ones(shape=(5, 6))
            expected = np.ones((5, 6))
            self.assertTrue(np.allclose(array2.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_ones(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.ones(shape=(3,))
            expected = np.array([1., 1., 1.])
            self.assertTrue(np.allclose(array1.to_array(), expected))

            array2 = manager.zeros(shape=(5, 6))
            expected = np.zeros((5, 6))
            self.assertTrue(np.allclose(array2.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_full(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.full([0., 1., 2.], shape=(3,))
            expected = np.array([0, 1, 2])
            self.assertTrue(np.allclose(array1.to_array(), expected))

            array2 = manager.full(4.5, shape=(6,))
            expected = np.full((6,), 4.5)
            self.assertTrue(np.allclose(array2.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_zeros_like(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.create([0, 1, 2], shape=(3,))
            zeros_like = array1.zeros_like()
            expected = np.array([0., 0., 0.])
            self.assertTrue(np.allclose(zeros_like.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_ones_like(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.create([0, 1, 2], shape=(3,))
            ones_like = array1.ones_like()
            expected = np.array([1., 1., 1.])
            self.assertTrue(np.allclose(ones_like.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_arange(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.arange(0, 10)
            expected = np.array([0., 1., 2., 3., 4., 5., 6., 7., 8., 9.])
            self.assertTrue(np.allclose(array1.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_eye(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.eye(2)
            expected = np.array([[1., 0.], [0., 1.]])
            self.assertTrue(np.allclose(array1.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_linspace(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.linspace(0, 10, shape=(100,))
            expected = np.linspace(0., 10., num=100)
            self.assertTrue(np.allclose(array1.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_random_integer(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.random_integer(0, 10, shape=(100,))
            mean = np.mean(array1.to_array())
            self.assertTrue(mean >= 5)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_random_uniform(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.random.uniform(-10, 10, shape=(100,))
            mean = np.mean(array1.to_array())
            self.assertTrue(mean >= -5)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_random_normal(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.random.normal(shape=(100,))
            mean = np.mean(array1.to_array())
            std = np.std(array1.to_array())

            self.assertTrue(mean >= -0.5)
            self.assertTrue(std <= 1)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_truncated_normal(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.truncated_normal(shape=(100,))
            mean = np.mean(array1.to_array())
            std = np.std(array1.to_array())

            self.assertTrue(mean >= -2)
            self.assertTrue(std <= 1)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_fixed_seed(self):
        try:
            manager = NDManager.new_base_manager()
            array1 = manager.random.uniform(-10, 10, shape=(100,))
            expected = np.array([-9.99999999, -9.99999999, ...])
            self.assertTrue(np.allclose(array1.to_array(), expected))

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == '__main__':
    unittest.main()
