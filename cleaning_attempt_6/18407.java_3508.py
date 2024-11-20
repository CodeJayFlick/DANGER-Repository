import unittest

class NodeTest(unittest.TestCase):

    def test_type(self):
        self.assertEqual(NodeType.LEAF.value, LeafNode(0).get_node_type())
        self.assertEqual(NodeType.AND.value, AndNode().get_node_type())
        self.assertEqual(NodeType.OR.value, OrNode().get_node_type())

    def test_leaf_node(self):
        timestamps = [1, 2, 3, 4, 5, 6, 7]
        batch_reader = FakedBatchReader(timestamps)
        leaf_node = LeafNode(batch_reader)
        index = 0
        while leaf_node.has_next():
            self.assertEqual(leaf_node.next(), timestamps[index])
            index += 1

    def test_or_node(self):
        ret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20]
        left = [1, 3, 5, 7, 9, 10, 20]
        right = [2, 3, 4, 5, 6, 7, 8]
        self.test_or(ret[:], left[:], right[:])
        self.test_or([], [], [])
        self.test_or([1], [1], [])
        self.test_or([1], [1], [1])
        self.test_or([1, 2], [1], [1, 2])
        self.test_or([1, 2, 3], [1, 2], [1, 2, 3])

    def test_or(self, ret, left, right):
        or_node = OrNode(LeafNode(FakedBatchReader(left)), LeafNode(FakedBatchReader(right)))
        index = 0
        while or_node.has_next():
            self.assertEqual(or_node.next(), ret[index])
            index += 1
        self.assertEqual(len(ret), index)

    def test_and(self):
        self.test_and([], [1, 2, 3, 4], [])
        self.test_and([5], [1, 2, 3, 4], [5, 6, 7])
        self.test_and([2], [1, 2, 3, 4], [2, 5, 6])
        self.test_and([1, 2, 3], [1, 2, 3, 4], [1, 2, 3])
        self.test_and([9], [1, 2, 3, 4, 9], [8, 9])

    def test_and(self, ret, left, right):
        and_node = AndNode(LeafNode(FakedBatchReader(left)), LeafNode(FakedBatchReader(right)))
        index = 0
        while and_node.has_next():
            self.assertEqual(and_node.next(), ret[index])
            index += 1
        self.assertEqual(len(ret), index)

if __name__ == '__main__':
    unittest.main()
