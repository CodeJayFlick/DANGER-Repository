import unittest
from collections import deque

class GTreeNode:
    def __init__(self, name):
        self.name = name
        self.children = []

    def add_node(self, node):
        self.children.append(node)

def depth_first_iterator(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node

def breadth_first_iterator(root):
    queue = deque([root])
    while queue:
        node = queue.popleft()
        yield node

class TreeIteratorTest(unittest.TestCase):

    def setUp(self):
        self.root = GTreeNode("root")
        self.node0 = GTreeNode("Node0")
        self.node1 = GTreeNode("Node1")
        self.node2 = GTreeNode("Node2")
        self.node0_0 = GTreeNode("Node0_0")
        self.node0_1 = GTreeNode("Node0_1")
        self.node1_0 = GTreeNode("Node1_0")

        self.root.add_node(self.node0)
        self.root.add_node(self.node1)
        self.root.add_node(self.node2)
        self.node0.add_node(self.node0_0)
        self.node0.add_node(self.node0_1)
        self.node1.add_node(self.node1_0)

    def test_depth_first(self):
        it = depth_first_iterator(self.root)
        self.assertTrue(next(it) is self.root)
        for node in [self.node0, self.node0_0, self.node0_1, self.node1, self.node1_0, self.node2]:
            self.assertEqual(next(it), node)

    def test_breadth_first(self):
        it = breadth_first_iterator(self.root)
        self.assertTrue(next(it) is self.root)
        for node in [self.node0, self.node1, self.node2, self.node0_0, self.node0_1, self.node1_0]:
            self.assertEqual(next(it), node)

if __name__ == '__main__':
    unittest.main()
