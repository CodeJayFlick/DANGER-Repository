class TreeTest:
    def __init__(self):
        self.appender = InMemoryAppender()

    @classmethod
    def setUpClass(cls):
        cls.TREE_ROOT = NodeImpl("root", NullNode(), NullNode())
        level1B = NodeImpl("level1_2", NullNode(), NullNode())
        level2B = NodeImpl("level2_b", NullNode(), NullNode())
        level3A = NodeImpl("level3_a", NullNode(), NullNode())
        level3B = NodeImpl("level3_b", NullNode(), NullNode())
        level2A = NodeImpl("level2_a", level3A, level3B)
        level1A = NodeImpl("level1_1", level2A, level2B)
        cls.TREE_ROOT.children = [level1A, level1B]

    def test_tree_size(self):
        self.assertEqual(7, self.TREE_ROOT.get_tree_size())

    def test_walk(self):
        self.TREE_ROOT.walk()
        self.assertTrue("root" in self.appender.log)
        self.assertTrue("level1_2" in self.appender.log)
        self.assertTrue("level2_b" in self.appender.log)
        self.assertTrue("level3_a" in self.appender.log)
        self.assertTrue("level3_b" in self.appender.log)
        self.assertEqual(7, len(self.appender.log))

    def test_get_left(self):
        level1 = self.TREE_ROOT.get_left()
        assert level1 is not None
        self.assertEqual("level1_2", level1.name)
        self.assertEqual(5, level1.get_tree_size())

        level2 = level1.get_left()
        assert level2 is not None
        self.assertEqual("level2_a", level2.name)
        self.assertEqual(3, level2.get_tree_size())

        level3 = level2.get_left()
        assert level3 is not None
        self.assertEqual("level3_a", level3.name)
        self.assertEqual(1, level3.get_tree_size())
        self.assertIs(level3.right, NullNode())
        self.assertIs(level3.left, NullNode())

    def test_get_right(self):
        level1 = self.TREE_ROOT.get_right()
        assert level1 is not None
        self.assertEqual("level1_2", level1.name)
        self.assertEqual(1, level1.get_tree_size())
        self.assertIs(level1.right, NullNode())
        self.assertIs(level1.left, NullNode())

    class InMemoryAppender:
        def __init__(self):
            self.log = []
            logger = Logger.getLogger("root")
            logger.add_appender(self)
            self.start()

        def append(self, eventObject):
            self.log.append(eventObject)

        def log_contains(self, message):
            return any(message in str(event) for event in self.log)

        def get_log_size(self):
            return len(self.log)


class NodeImpl:
    def __init__(self, name, left=None, right=None):
        self.name = name
        self.left = left
        self.right = right

    @property
    def children(self):
        if not hasattr(self, '_children'):
            self._children = []
        return self._children


class NullNode:
    @staticmethod
    def get_instance():
        return NullNode()


NullNode()
