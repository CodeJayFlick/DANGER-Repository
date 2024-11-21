class PriorityMessageQueue:
    def __init__(self):
        self.queue = []

    def add(self, item):
        self.queue.append(item)

    def remove(self):
        if not self.is_empty():
            return self.queue.pop(0)
        else:
            return None

    def is_empty(self):
        return len(self.queue) == 0


import unittest
from unittest.mock import patch

class TestPriorityMessageQueue(unittest.TestCase):

    @patch('builtins.print')
    def test_remove(self, mock_print):
        queue = PriorityMessageQueue()
        item = "test"
        queue.add(item)
        self.assertEqual(queue.remove(), item)

    @patch('builtins.print')
    def test_add(self, mock_print):
        queue = PriorityMessageQueue()
        queue.add(1)
        queue.add(5)
        queue.add(10)
        queue.add(3)
        self.assertEqual(queue.remove(), 10)

    @patch('builtins.print')
    def test_is_empty(self, mock_print):
        queue = PriorityMessageQueue()
        self.assertTrue(queue.is_empty())
        queue.add(1)
        queue.remove()
        self.assertTrue(queue.is_empty())

    @patch('builtins.print')
    def test_ensure_size(self, mock_print):
        queue = PriorityMessageQueue()
        self.assertTrue(queue.is_empty())
        queue.add(1)
        queue.add(2)
        queue.add(2)
        queue.add(3)
        self.assertEqual(queue.remove(), 3)


if __name__ == '__main__':
    unittest.main()
