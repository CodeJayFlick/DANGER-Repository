Here is the equivalent Python code:

```Python
import unittest
from io import BytesIO

class TSFInputSplitTest(unittest.TestCase):

    def setUp(self):
        self.w_input_split = TSFInputSplit(Path("input"), ["192.168.1.1", "192.168.1.0", "localhost"], 30, 100)
        self.r_input_split = TSFInputSplit()

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertEqual'), reason='Old Python version')
    def test_input_split_write_and_read(self):
        try:
            # call the write method to serialize the object
            w_input_split.write(BytesIO())
            r_input_split.read_fields(w_input_split)
            self.assertEqual(w_input_split.path, r_input_split.path)
            self.assertEqual(w_input_split.start, r_input_split.start)
            self.assertEqual(w_input_split.length, r_input_split.length)

        except Exception as e:
            print(str(e))
            self.fail()

if __name__ == '__main__':
    unittest.main()
```

Note: Python does not have direct equivalent of Java's `@Before` and `@Test`. The setup method is used to initialize the test case.