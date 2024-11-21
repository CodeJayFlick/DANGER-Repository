import unittest
from collections import defaultdict

class OrganizationNodeTest(unittest.TestCase):

    def testOrganizeDoesNothingIfBelowMaxGroupSize(self):
        nodes = ["AAA", "AAB", "AAB", "AABA", "BBA", "BBB", "BBC", "CCC", "DDD"]
        result = organize(nodes, 10)
        self.assertEqual(nodes, result)

    def testBasicPartitioning(self):
        nodes = ["AAA", "AAB", "AAC", "BBA", "BBB", "BBC", "CCC", "DDD"]
        result = organize(nodes, 5)
        self.assertEqual(4, len(result))
        self.assertEqual("AA", result[0].name())
        self.assertEqual("BB", result[1].name())
        self.assertEqual("CCC", result[2].name())
        self.assertEqual("DDD", result[3].name())

    def testMultiLevel(self):
        nodes = ["A", "B", "CAA", "CAB", "CAC", "CAD", "CAE", "CAF", "CBA"]
        result = organize(nodes, 5)
        self.assertEqual(3, len(result))
        self.assertEqual("A", result[0].name())
        self.assertEqual("B", result[1].name())
        self.assertEqual("C", result[2].name())

    def testManySameLabels(self):
        nodes = ["A"] + ["DUP" for _ in range(20)]
        result = organize(nodes, 5)
        self.assertEqual(2, len(result))
        self.assertEqual("A", result[0].name())
        self.assertEqual("DUP", result[1].name())

    def testRemoveNotShownNode(self):
        nodes = ["A"] + ["D" for _ in range(20)] + ["DUP" for _ in range(10)]
        result = organize(nodes, 5)
        d_node = result[1]
        dup_node = d_node.children[2]
        self.assertEqual(dup_node.child_count(), OrganizationNode.MAX_SAME_NAME + 1)

    def testRemoveShownNode(self):
        nodes = ["A"] + ["D" for _ in range(20)] + ["DUP" for _ in range(10)]
        result = organize(nodes, 5)
        d_node = result[1]
        dup_node = d_node.children[2]
        self.assertEqual(dup_node.child_count(), OrganizationNode.MAX_SAME_NAME)

    def testAddDupNodeJustIncrementsCount(self):
        nodes = ["A"] + ["D" for _ in range(20)] + ["DUP" for _ in range(10)]
        result = organize(nodes, 5)
        d_node = result[1]
        dup_node = d_node.children[2]
        self.assertEqual(dup_node.child_count(), OrganizationNode.MAX_SAME_NAME)

    def testEmptyNodeIsRemoved(self):
        nodes = ["AA1", "AA2", "AA3", "AB1", "AB2", "AB3", "BB1", "BB2", "BB3", "CCC", "DDD"]
        result = organize(nodes, 3)
        self.assertEqual(4, len(result))
        node_a = result[0]
        self.assertEqual("A", node_a.name())

    def simulate_smbol_deleted(self, root, symbol_to_delete):
        key = SymbolNode.create_key_node(symbol_to_delete, symbol_to_delete.name(), None)
        found = root.find_symbol_tree_node(key, False, TaskMonitor.DUMMY)
        Swing.run_now(lambda: found.get_parent().remove_node(found))

    def organize(self, list_nodes, size):
        try:
            return OrganizationNode.organize(list_nodes, size, TaskMonitor.DUMMY)
        except CancelledException as e:
            raise AssertException("Can't happen") from e

    def nodes(self, *names):
        list_nodes = []
        for name in names:
            list_nodes.append(node(name))
        return list_nodes

    def node(self, name):
        return CodeSymbolNode(None, StubSymbol(name, None))

if __name__ == "__main__":
    unittest.main()
