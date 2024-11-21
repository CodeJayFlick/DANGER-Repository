import unittest
from abc import ABCMeta, abstractmethod

class GTreeEventTest(unittest.TestCase):

    def setUp(self):
        self.g_tree = None
        self.events = []

    def test_node_added(self):
        root = TestRootNode()
        self.g_tree = GTree(root)
        self.g_tree.get_model().add_tree_model_listener(TestTreeModelListener())
        win_mgr = DockingWindowManager(DummyTool(), None)
        win_mgr.add_component(TestTreeComponentProvider(self.g_tree))
        win_mgr.set_visible(True)

    def test_changing_parent_node_while_filtered(self):
        model_root = TestRootNode()
        self.g_tree.set_root_node(model_root)
        create_nodes(model_root, "A")
        create_nodes(model_root, "B")
        create_nodes("B", "B1", "B2", "B3")

    def assert_event(self, view_b, event_type):
        self.assertTrue(len(self.events) > 0)
        event = self.events[0]
        self.assertEqual(event_type, event.event_type)

class GTreeNode:
    pass

class DummyTool:
    pass

class TestRootNode(GTreeNode):
    pass

class LeafNode(GTreeNode):
    def __init__(self, name):
        super().__init__()
        self.name = name

class NamedNode(GTreeNode):
    def __init__(self, name):
        super().__init__()
        self.name = name

class TreeEvent:
    def __init__(self, event_type, event):
        self.event_type = event_type
        self.event = event

if __name__ == '__main__':
    unittest.main()
