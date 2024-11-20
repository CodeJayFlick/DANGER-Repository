Here is the equivalent Python code:

```Python
import unittest
from io import StringIO
import sys

class NDListGeneratorTest(unittest.TestCase):

    def test_help(self):
        args = ["ndlist-gen", "-h"]
        with open(StringIO(), 'w') as f:
            with redirect_stdout(f):
                Benchmark.main(args)

    def test_missing_options(self):
        args = ["ndlist-gen", "-s"]
        self.assertFalse(NDListGenerator.generate(args))

    def test_ones(self):
        args = ["ndlist-gen", "-s", "1", "-o", "build/ones.ndlist", "-1"]
        self.assertTrue(NDListGenerator.generate(args))

    def test_zeros(self):
        args = ["ndlist-gen", "-s", "1", "-o", "build/zeros.ndlist"]
        self.assertTrue(NDListGenerator.generate(args))


if __name__ == '__main__':
    unittest.main()
```

This Python code is equivalent to the Java code provided. It uses the `unittest` module for unit testing and the `StringIO` class from the `io` module to simulate a file object in memory.

The `Benchmark` class and its methods are not defined here, as they were part of the original Java code. You would need to define these classes or functions yourself if you want to use them with this Python test code.

Note: The redirect_stdout function is used to capture the output of Benchmark.main() method in memory instead of printing it to console.