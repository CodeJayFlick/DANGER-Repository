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
