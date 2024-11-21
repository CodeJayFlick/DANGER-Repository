import unittest
from threading import Thread
from time import sleep
import random

class GTreeSlowLoadingNodeTest(unittest.TestCase):

    def setUp(self):
        self.g_tree = GTree(EmptyRootNode())
        self.frame = JFrame("GTree Test")
        self.frame.get_contentpane().add(self.g_tree)
        self.frame.set_size(400, 400)
        self.frame.set_visible(True)

    def tearDown(self):
        self.g_tree.dispose()
        self.frame.dispose()

    @unittest.skip
    def testBasicLoading(self):
        self.g_tree.set_root_node(TestRootNode(100))

        while not is_tree_loaded():
            sleep(0.1)

        root = self.g_tree.get_modelroot()
        non_leaf_1 = root.get_child(0)
        leaf_1 = root.get_child(1)
        non_leaf_2 = root.get_child(2)

        child_count = non_leaf_1.get_childcount()
        assert(child_count > 1), "Did not find children for: {}".format(non_leaf_1)
        self.assertEqual(leaf_1.get_childcount(), 0, "An expected leaf node has some children")

    @unittest.skip
    def testSlowNodeShowsProgressBar(self):
        self.g_tree.set_root_node(TestRootNode(5000))

        while not is_tree_loaded():
            sleep(0.1)

        root = self.g_tree.get_modelroot()
        non_leaf_1 = root.get_child(0)
        assert(non_leaf_1.is_not_loaded())

        self.g_tree.expand_path(non_leaf_1)

        self.assertTrue(is_progress_panel_shown())
        self.assertFalse(non_leaf_1.is_loaded())

        press_cancel_button()

        while is_progress_panel_shown():
            sleep(0.1)

    @unittest.skip
    def testSlowNodeShowsProgressBarFromSwingAccess(self):
        self.g_tree.set_root_node(TestRootNode(5000))

        while not is_tree_loaded():
            sleep(0.1)

        root = self.g_tree.get_modelroot()
        non_leaf_1 = root.get_child(0)
        children = Swing.run_now(lambda: non_leaf_1.get_children())
        assert(len(children) == 1), "Did not find expected child"
        self.assertTrue(isinstance(children[0], InProgressGTreeNode))

        self.assertTrue(is_progress_panel_shown())

    @unittest.skip
    def testInProgress(self):
        self.g_tree.set_root_node(TestRootNode(100))

        while not is_tree_loaded():
            sleep(0.1)

        root = self.g_tree.get_modelroot()
        non_leaf_1 = root.get_child(0)
        children = Swing.run_now(lambda: non_leaf_1.get_children())
        assert(len(children) == 3), "Did not find expected child count"
        for child in children:
            if isinstance(child, InProgressGTreeNode):
                self.assertTrue(is_progress_panel_shown())

    def is_tree_loaded(self):
        return True

    def is_progress_panel_shown(self):
        return False

    def press_cancel_button(self):
        pass


class EmptyRootNode(GTreeSlowLoadingNode):

    def __init__(self):
        super().__init__()
        self.set_children([])


class TestRootNode(GTreeNode):

    def __init__(self, load_delay_millis):
        super().__init__()
        children = []
        for _ in range(3):
            if random.randint(0, 1) == 0:
                children.append(TestSlowLoadingNode(load_delay_millis, 1))
            else:
                children.append(TestLeafNode())
        self.set_children(children)


class TestSlowLoadingNode(GTreeSlowLoadingNode):

    def __init__(self, load_delay_millis, depth):
        super().__init__()
        self.load_delay_millis = load_delay_millis
        self.depth = depth

    def generate_children(self, monitor):
        if self.depth > 4:
            return []
        sleep(self.load_delay_millis)
        while pause_child_loading:
            sleep(0.1)

        child_count = random.randint(MIN_CHILD_COUNT, MAX_CHILD_COUNT)
        children = []
        for _ in range(child_count):
            monitor.check_canceled()
            if random.randint(0, 1) == 0:
                children.append(TestSlowLoadingNode(self.load_delay_millis, self.depth + 1))
            else:
                children.append(TestLeafNode())
        return children


class TestLeafNode(GTreeNode):

    def __init__(self):
        super().__init__()
        self.name = "TestLeafNode"


if __name__ == "__main__":
    unittest.main()
