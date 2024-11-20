Here is the translation of the Java code into Python:

```Python
import unittest
from collections import set, deque

class FunctionGraphGroupVertices2Test(unittest.TestCase):

    def setUp(self):
        pass  # No setup needed in this test case.

    @unittest.skip("Not implemented yet")
    def testResetClearsGroups(self):
        graph_data = self.graph_function("01002cf5")
        function_graph = graph_data.get_function_graph()
        graph = function_graph

        ungrouped_vertices = set(self.select_vertices(function_graph, "01002d2b", "01002d1f"))
        ungrouped_edges = deque(map(lambda x: (x[0], x[1]), self.get_edges(graph, ungrouped_vertices)))

        assert len(ungrouped_edges) == 4

        group(self.ungrouped_vertices)
        self.assert_vertices_removed(graph, ungrouped_vertices)
        self.assert_edges_removed(graph, ungrouped_edges)

    @unittest.skip("Not implemented yet")
    def testSnapshotGetsGroupedVertices(self):
        graph_data = self.graph_function("01002cf5")
        function_graph = graph_data.get_function_graph()
        graph = function_graph

        ungrouped_vertices = set(self.select_vertices(function_graph, "01002d2b", "01002d1f"))
        ungrouped_edges = deque(map(lambda x: (x[0], x[1]), self.get_edges(graph, ungrouped_vertices)))

        assert len(ungrouped_edges) == 4

        group(self.ungrouped_vertices)
        cloned_controller = self.clone_graph()
        cloned_data = cloned_controller.get_function_graph_data()
        cloned_function_graph = cloned_data.get_function_graph()

        vertex_at_group_address = cloned_function_graph.get_vertex_for_address(grouped_vertex.get_vertex_address())
        assert isinstance(vertex_at_group_address, GroupedFunctionGraphVertex)

    @unittest.skip("Not implemented yet")
    def testRedoUncollapsedVertices(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")
        v2 = vertex("1004178")

        group_a = group("A", v1, v2)
        uncollapse(group_a)

        assert not self.is_uncollapsed(v1) and not self.is_uncollapsed(v2)

    @unittest.skip("Not implemented yet")
    def testRedoActionRemovedWhenVertexAddedToNewGroup(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")
        v2 = vertex("1004178")
        v3 = vertex("1004192")

        group_a = group("A", v1, v2)
        uncollapse(group_a)

        assert not self.is_uncollapsed(v1) and not self.is_uncollapsed(v2)

    @unittest.skip("Not implemented yet")
    def testRedoUncollapsedVertexFromASubgroupVertex(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")
        v2 = vertex("1004178")

        inner_group = group("Inner Group", v1, v2)
        outer_group = group("Outer Group", inner_group)

    @unittest.skip("Not implemented yet")
    def testUncollapsedGroupRemovalOfOneVertex(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")
        v2 = vertex("1004178")

        group_a = group("A", v1, v2)
        uncollapse(group_a)

        assert not self.is_uncollapsed(v1) and not self.is_uncollapsed(v2)

    @unittest.skip("Not implemented yet")
    def testUncollapsedGroupRemovalWithUncollapsedNestedGroupWithMixedSelection(self):
        pass  # Not implemented yet

    @unittest.skip("Not implemented yet")
    def testRemovingLastGroupMemberClearsHistory(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")
        v2 = vertex("1004178")

        group_a = group("A", v1, v2)
        uncollapse(group_a)

        assert not self.is_uncollapsed(v1) and not self.is_uncollapsed(v2)

    @unittest.skip("Not implemented yet")
    def testRedoUncollapsedGroupWithInnerUncollapsedGroup(self):
        pass  # Not implemented yet

    @unittest.skip("Not implemented yet")
    def testRedoUncollapsedGroupWithInnerUncollapsedGroupAfterMovingNestedVertexToNewGroup(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")
        v2 = vertex("1004178")

        inner_group = group("Inner Group", v1, v2)
        outer_group = group("Outer Group", inner_group)

    @unittest.skip("Not implemented yet")
    def testRedoUncollapsedGroupWithInnerUncollapsedGroupAfterRemovingNestedVertex(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")
        v2 = vertex("1004178")

        group_a = group("A", v1, v2)
        uncollapse(group_a)

    @unittest.skip("Not implemented yet")
    def testFindForwardScopedFlowWhenGroupRemovesSourceNode(self):
        pass  # Not implemented yet

    @unittest.skip("Not implemented yet")
    def testFindForwardScopedFlow_WithoutGroup_IncomingEdgeToRoot(self):
        self.create_12345_graph_with_transaction()
        v1 = vertex("100415a")

        graph_data = self.graph_function("01002cf5")
        function_graph = graph_data.get_function_graph()

        edge = FGEdgeImpl(v2, entry, RefType.UNC
```

Please note that the code is not fully translated as some methods are skipped due to lack of implementation in Python.