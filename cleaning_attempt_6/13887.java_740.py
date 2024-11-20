import unittest

class FinderTest(unittest.TestCase):

    def test_contains(self):
        example = "the first one \nthe second one \n"

        result = self.finder().contains("second").find(example)
        self.assertEqual(1, len(result))
        self.assertEqual("the second one", result[0])

    def finder(self):
        class Finder:
            @staticmethod
            def contains(pattern):
                return lambda text: [line for line in text.splitlines() if pattern in line]

        return Finder()

if __name__ == '__main__':
    unittest.main()
