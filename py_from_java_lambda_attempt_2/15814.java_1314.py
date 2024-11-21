Here is the equivalent Python code:

```Python
import os
import unittest
from io import StringIO

class UtilsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            os.rmdir('build/tmp/testFile')
        except FileNotFoundError:
            pass

    @classmethod
    def tearDownClass(cls):
        try:
            os.rmdir('build/tmp/testFile')
        except FileNotFoundError:
            pass

    def test_contains(self):
        words = ["Hello World", "2"]
        self.assertTrue(Utils.contains(words, "2"))
        self.assertFalse(Utils.contains(words, "3"))

    def test_pad(self):
        sb = StringIO()
        sb.write("Hello")
        Utils.pad(sb, 'a', 5)
        self.assertEqual(sb.getvalue(), "Helloaaaa")

    def test_file(self):
        dir_path = 'build/tmp/testFile'
        os.makedirs(dir_path, exist_ok=True)
        file_path = os.path.join(dir_path, 'synset.txt')
        with open(file_path, 'w') as f:
            pass
        self.assertEqual(Utils.read_lines(file_path), [])

        with open(file_path, 'a') as f:
            f.write("line1\n")

        self.assertEqual(len(Utils.read_lines(file_path)), 1)

        Utils.delete_quietly(dir_path)
        self.assertFalse(os.path.exists(dir_path))

    def test_to_float_array(self):
        list_ = [1, 2]
        array = Utils.to_float_array(list_)
        self.assertEqual(array, [1.0, 2.0])

if __name__ == '__main__':
    unittest.main()
```

Note: The equivalent Python code does not include the `@BeforeClass` and `@AfterClass` annotations as they are specific to JUnit testing framework in Java. In Python, you can use setUpClass() and tearDownClass() methods for similar functionality.