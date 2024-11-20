import numpy as np

class NDArrayLogicalOpTest:
    def test_logical_and(self):
        try:
            manager = ndmanager()
            array1 = manager.create([True, False])
            array2 = manager.create([False, False])
            expected = manager.create([False, False])
            self.assertEqual(array1.logical_and(array2), expected)
            self.assertEqual(NDArrays.logical_and(array1, array2), expected)

            array1 = manager.arange(10).astype(bool)
            array2 = manager.arange(10).astype(bool)
            expected = manager.zeros((10,), dtype=bool)
            self.assertEqual(array1.logical_and(array2), expected)
            self.assertEqual(NDArrays.logical_and(array1, array2), expected)

            # test multi-dim
            array1 = manager.create([True, True, False, False], shape=(4,))
            array2 = manager.create([False, False, True, True], shape=(4,))
            expected = manager.create([False, False, False, False], shape=(4,))
            self.assertEqual(array1.logical_and(array2), expected)
            self.assertEqual(NDArrays.logical_and(array1, array2), expected)

            # test scalar
            array1 = manager.ones((1,), dtype=bool)
            array2 = manager.array([[True, False, False, True]], dtype=bool).reshape(-1,)
            expected = manager.array([[False, True, True, True]]).astype(bool)
            self.assertEqual(array1.logical_and(array2), expected)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_logical_or(self):
        try:
            manager = ndmanager()
            array1 = manager.create([True, False, True, False])
            array2 = manager.create([False, True, False, True])
            expected = manager.create([True, True, True, True])
            self.assertEqual(array1.logical_or(array2), expected)
            self.assertEqual(NDArrays.logical_or(array1, array2), expected)

            array1 = manager.arange(10).astype(bool)
            array2 = manager.arange(10).astype(bool)
            expected = manager.ones((10,), dtype=bool)
            self.assertEqual(array1.logical_or(array2), expected)
            self.assertEqual(NDArrays.logical_or(array1, array2), expected)

            # test multi-dim
            array1 = manager.create([False, False, False, False], shape=(4,))
            array2 = manager.create([True, True, True, True], shape=(4,))
            expected = manager.create([True, True, True, True], shape=(4,))
            self.assertEqual(array1.logical_or(array2), expected)
            self.assertEqual(NDArrays.logical_or(array1, array2), expected)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_logical_xor(self):
        try:
            manager = ndmanager()
            array1 = manager.create([True, False, True, False])
            array2 = manager.create([True, True, False, False])
            expected = manager.create([False, True, True, False])
            self.assertEqual(array1.logical_xor(array2), expected)
            self.assertEqual(NDArrays.logical_xor(array1, array2), expected)

            array1 = manager.arange(-5.0, 5.0).reshape((2, 1, 5)).astype(bool)
            array2 = manager.arange(5.0, -5.0, -1.0).reshape((2, 1, 5)).astype(bool)
            expected = manager.zeros((2, 1, 5), dtype=bool)
            self.assertEqual(array1.logical_xor(array2), expected)
            self.assertEqual(NDArrays.logical_xor(array1, array2), expected)

        except Exception as e:
            print(f"An error occurred: {e}")

    def test_logical_not(self):
        try:
            manager = ndmanager()
            array = manager.create([-2.0, 0.0, 1.0])
            expected = manager.create([False, True, False], dtype=bool)
            self.assertEqual(array.logical_not(), expected)

            array = manager.array([[1.0, 2.0, -1.0, -2.0]], dtype=float).reshape(-1,)
            expected = manager.array([[False, False, False, False]]).astype(bool)
            self.assertEqual(array.logical_not(), expected)

        except Exception as e:
            print(f"An error occurred: {e}")

def ndmanager():
    return np

if __name__ == "__main__":
    test = NDArrayLogicalOpTest()
    test.test_logical_and()
    test.test_logical_or()
    test.test_logical_xor()
    test.test_logical_not()

