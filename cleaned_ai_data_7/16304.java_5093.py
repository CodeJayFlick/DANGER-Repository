import numpy as np

class PaddingStackBatchifierTest:
    def test_batchify(self):
        manager = NDManager.new_base_manager()
        input = [manager.zeros((10, i+1)) for i in range(5)]
        batchifier = Batchifier.builder().opt_include_valid_lengths(False).add_pad(0, 1, lambda mngr: mngr.zeros((10, 1))).build()

        actual = batchifier.batchify(input)

        self.assertEqual(len(actual), 2)
        self.assertEqual(actual[0].shape, (5, 10, 5))
        self.assertEqual(actual[1].shape, (5,))
        for array in input:
            self.assertEqual(array.name, "array1" if i < 4 else "array2")

    def test_batchify_with_valid_length(self):
        manager = NDManager.new_base_manager()
        valid_lengths = [i+1 for i in range(5)]
        input = [manager.zeros((10, length)) for length in valid_lengths]
        batchifier = Batchifier.builder().opt_include_valid_lengths(True).add_pad(0, 1, lambda mngr: mngr.zeros((10, 1))).build()

        actual = batchifier.batchify(input)

        self.assertEqual(len(actual), 3)
        self.assertEqual(actual[0].shape, (5, 10, 5))
        self.assertEqual(actual[1].shape, (5,))
        self.assertEqual(actual[2], manager.create(valid_lengths))

    def test_batchify_with_padding_size(self):
        manager = NDManager.new_base_manager()
        input = [manager.zeros((10, i+1)) for i in range(5)]
        batchifier = Batchifier.builder().opt_include_valid_lengths(False).add_pad(0, 1, lambda mngr: mngr.zeros((10, 1)), 13).build()

        actual = batchifier.batchify(input)

        self.assertEqual(len(actual), 2)
        self.assertEqual(actual[0].shape, (5, 10, 13))
        self.assertEqual(actual[1].shape, (5,))

    def test_unbatchify(self):
        manager = NDManager.new_base_manager()
        input = [manager.zeros((10, 11)), manager.zeros((10))]
        batchifier = Batchifier.builder().opt_include_valid_lengths(False).add_pad(0, 1, lambda mngr: mngr.zeros((10, 1))).build()

        actual = batchifier.unbatchify(input)

        self.assertEqual(len(actual), 2)
        for arrays in actual:
            self.assertEqual(len(arrays), 2)
            self.assertEqual(arrays[0].shape, (11,))
            self.assertEqual(arrays[1].shape, ())

    def test_unbatchify_with_valid_lengths(self):
        manager = NDManager.new_base_manager()
        valid_lengths = [3, 1, 7, 11]
        input = [manager.zeros((4, 11)), manager.zeros((4))]
        batchifier = Batchifier.builder().opt_include_valid_lengths(True).add_pad(0, 1, lambda mngr: mngr.zeros((4, 1))).build()

        actual = batchifier.unbatchify(input)

        self.assertEqual(len(actual), 4)
        for i in range(4):
            arrays = actual[i]
            self.assertEqual(len(arrays), 2)
            self.assertEqual(arrays[0].shape, (valid_lengths[i],))
            self.assertEqual(arrays[1].shape, ())

    def test_split(self):
        manager = NDManager.new_base_manager()
        input = [manager.zeros((10, 11)), manager.zeros((10))]
        batchifier = Batchifier.builder().opt_include_valid_lengths(False).add_pad(0, 1, lambda mngr: mngr.zeros((10, 1))).build()

        actual = batchifier.split(input, 3, False)

        self.assertEqual(len(actual), 3)
        for i in range(2):
            arrays = actual[i]
            self.assertEqual(len(arrays), 2)
            self.assertEqual(arrays[0].shape, (4, 11))
            self.assertEqual(arrays[1].shape, (4,))
        last_arrays = actual[-1]
        self.assertEqual(len(last_arrays), 2)
        self.assertEqual(last_arrays[0].shape, (2, 11))
        self.assertEqual(last_arrays[1].shape, (2))

    def test_split_with_valid_lengths(self):
        manager = NDManager.new_base_manager()
        valid_lengths = [3, 1, 11]
        input = [manager.zeros((3, 11)), manager.zeros((3))]
        batchifier = Batchifier.builder().opt_include_valid_lengths(True).add_pad(0, 1, lambda mngr: mngr.zeros((3, 1))).build()

        actual = batchifier.split(input, 2, False)

        self.assertEqual(len(actual), 2)
        arrays = actual[0]
        self.assertEqual(len(arrays), 3)
        for i in range(3):
            self.assertEqual(arrays[i].shape, (2 if i < 2 else 1, 11))
        last_arrays = actual[-1]
        self.assertEqual(len(last_arrays), 3)
        for i in range(3):
            self.assertEqual(last_arrays[i].shape, (1 if i < 2 else 0, 11))

if __name__ == "__main__":
    import unittest
    suite = unittest.TestLoader().loadTestsFromTestCase(PaddingStackBatchifierTest)
    unittest.TextTestRunner().run(suite)

