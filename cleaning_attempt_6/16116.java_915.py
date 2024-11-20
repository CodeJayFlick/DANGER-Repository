import unittest
from tensorflow.lite.python import tflite

class TfLiteNDManagerTest(unittest.TestCase):

    def test_nd_array(self):
        if 'win' in platform.system().lower():
            raise unittest.SkipTest("test only work on mac and Linux")

        with tflite.TFLITE as manager:
            zeros = manager.zeros((1, 2))
            data = zeros.numpy()
            self.assertEqual(data[0], 0)

            ones = manager.ones((1, 2))
            data = ones.numpy()
            self.assertEqual(data[0], 1)

            array = manager.create([0.0, 1.0, 2.0, 3.0])
            expected = [0.0, 1.0, 2.0, 3.0]
            self.assertListEqual(array.numpy().tolist(), expected)


if __name__ == '__main__':
    unittest.main()
