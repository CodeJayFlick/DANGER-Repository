Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the `IntIndexManager` class and its methods (`allocate`, `deallocate`, and `clear`) since they were not provided. You will need to implement these classes and methods in Python for this code to work.

Also, I used the built-in `unittest` module in Python to write a test case. The `test_int_index_manager` method is the equivalent of the Java `testIntIndexManager()` method.