import unittest
from collections import deque

class StackTest(unittest.TestCase):

    def setUp(self):
        self.stack1 = deque(maxlen=25)
        self.stack2 = deque(["1", "2"])
        self.stack3 = deque(["A"])
        self.stack4 = deque(["1", "2"])

    def tearDown(self):
        self.stack1 = None
        self.stack2 = None
        self.stack3 = None
        self.stack4 = None

    def test_search(self):
        self.assertEqual(0, list(self.stack4).index("1"))
        self.assertEqual(1, list(self.stack4).index("2"))
        self.assertRaises(ValueError, lambda: list(self.stack4).index("3"))

    def test_pop(self):
        self.assertEqual("A", self.stack3.pop())
        with self.assertRaises(IndexError):
            self.stack2.pop()
        self.assertEqual(True, "3" in [self.stack2.append(i) for i in ["1", "2", "3"]])
        self.assertEqual("3", self.stack2.pop())

    def test_push(self):
        self.assertEqual("3", self.stack2.appendleft("3"))
        self.assertEqual("3", self.stack2.pop(0))

    def test_equals(self):
        self.assertTrue(self.stack1 == self.stack1)
        self.assertFalse(self.stack1 == self.stack2)
        self.assertTrue(self.stack2 == self.stack4)

    def test_empty(self):
        self.assertTrue(self.stack1.empty())
        self.assertFalse(self.stack2.empty())
        self.assertFalse(self.stack3.empty())

    def test_peek(self):
        self.assertEqual("2", list(self.stack2)[-1])
        self.assertEqual("A", list(self.stack3)[-1])

if __name__ == '__main__':
    unittest.main()
