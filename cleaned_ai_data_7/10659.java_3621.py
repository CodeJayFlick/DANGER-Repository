import unittest

class IntIndexManagerTest(unittest.TestCase):
    def __init__(self):
        super().__init__()

    def test_int_index_manager(self):
        imgr = IntIndexManager()

        print("test basic allocation")
        for i in range(10):
            self.assertEqual(i, imgr.allocate())

        print("test deallocation")
        for i in range(5, 8):
            imgr.deallocate(i)
        for i in range(7, 4, -1):
            self.assertEqual(i, imgr.allocate())
        self.assertEqual(10, imgr.allocate())

        print("test clear all")
        imgr.clear()
        for i in range(10):
            self.assertEqual(i, imgr.allocate())

if __name__ == '__main__':
    unittest.main()
