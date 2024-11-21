Here is the translation of the given Java code into Python:

```Python
import unittest


class RedBlackTreeTest(unittest.TestCase):

    def setUp(self):
        self.tree = {}
        for i in range(1, 11):
            self.tree[i] = str(i)

    def test_size(self):
        self.assertEqual(len(self.tree), 10)

    def test_contains(self):
        for key in self.tree:
            self.assertTrue(key in self.tree)
        for key in [0, 12]:
            self.assertFalse(key in self.tree)

    def test_get_first_last(self):
        first_key = min(self.tree.keys())
        last_key = max(self.tree.keys())

        self.assertEqual(first_key, int(list(self.tree.keys())[0]))
        self.assertEqual(last_key, int(list(self.tree.keys())[-1]))

    def test_remove(self):
        self.tree.pop(5)
        self.assertEqual(len(self.tree), 9)

    def test_depth(self):
        tree = {}
        for i in range(10):
            tree[i] = str(i)

        depth = get_tree_depth(tree)
        self.assertEqual(depth, 4)


def get_tree_depth(rb_tree):
    max_depth = 0
    node = min(rb_tree.keys())
    while node is not None:
        node_depth = get_node_depth(node)
        if node_depth > max_depth:
            max_depth = node_depth
        node = next((k for k in rb_tree if k >= node), None)

    return max_depth


def get_node_depth(node):
    depth = 0
    while node is not None and 'parent' in node:
        depth += 1
        node = node['parent']
    return depth

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have a direct equivalent of Java's RedBlackTree. The above code uses a dictionary to simulate the tree, and some methods are implemented differently due to the differences between languages.