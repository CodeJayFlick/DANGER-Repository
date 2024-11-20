class NullNodeTest:
    def test_get_instance(self):
        instance = NullNode.get_instance()
        self.assertIsNotNone(instance)
        self.assertIs(instance, NullNode.get_instance())

    def test_fields(self):
        node = NullNode.get_instance()
        self.assertEqual(0, node.tree_size())
        self.assertIsNone(node.name)
        self.assertIsNone(node.left)
        self.assertIsNone(node.right)

import unittest
from your_module import NullNode  # replace 'your_module' with the actual name of your module

class TestNullNode(unittest.TestCase):
    def test_get_instance(self):
        instance = NullNode.get_instance()
        self.assertIsNotNone(instance)
        self.assertIs(instance, NullNode.get_instance())

    def test_fields(self):
        node = NullNode.get_instance()
        self.assertEqual(0, node.tree_size())
        self.assertIsNone(node.name)
        self.assertIsNone(node.left)
        self.assertIsNone(node.right)

if __name__ == '__main__':
    unittest.main()
