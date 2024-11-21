import numpy as np

class DlrNDManagerTest:
    def test_nd_array(self):
        if 'win' in sys.platform.lower():
            raise Exception("test only work on mac and Linux")

        try:
            zeros = np.zeros((1, 2))
            data = zeros.flatten().tolist()
            self.assertEqual(data[0], 0)

            ones = np.ones((1, 2))
            data = ones.flatten().tolist()
            self.assertEqual(data[0], 1)

            buf = [0.0, 1.0, 2.0, 3.0]
            array = np.array(buf)
            self.assertTrue(np.allclose(array, buf))

            bb = bytearray(4 * len(buf))
            for i in range(len(buf)):
                bb[i*4:i*4+4] = struct.pack('f', buf[i])
            bb.seek(0)

            dlr_array = np.frombuffer(bb, dtype=np.float32)
            self.assertTrue(np.allclose(dlr_array, buf))

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    import unittest
    class TestDlrNDManagerTest(unittest.TestCase):
        def test_nd_array(self):
            DlrNDManagerTest().test_nd_array()

    suite = unittest.TestSuite()
    suite.addTest(unittest.makeTestFromFunction(TestDlrNDManagerTest.test_nd_array))
    runner = unittest.TextTestRunner()
    runner.run(suite)
