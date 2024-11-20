import unittest
from collections import defaultdict

class TestV:
    def __init__(self, id):
        self.id = str(id)

    def __str__(self):
        return self.id

    def __eq__(self, other):
        if not isinstance(other, TestV):
            return False
        return self.id == other.id


class TestE(GEdge[TestV]):
    def __init__(self, start: TestV, end: TestV):
        super().__init__(start, end)


class AbstractGraphAlgorithmsTest(unittest.TestCase):

    def setUp(self) -> None:
        pass

    @staticmethod
    def create_graph() -> GDirectedGraph[object, object]:
        return defaultdict(list)

    def assert_contains_edges_exactly(self, graph: dict, edges: list):
        self.assertEqual(set(graph.keys()), set([edge.start for edge in edges]))
        self.assertEqual(len(edges), len(graph))

    @staticmethod
    def result_edge(v1: TestV, v2: TestV) -> object:
        return (v1, v2)

    def start_memory_monitor_thread(self):
        pass

    def generate_simply_connected_graph(self, n_vertices: int) -> list[TestV]:
        vertices = [TestV(i) for i in range(n_vertices)]
        edges = [(vertices[i], vertices[(i + 1) % n_vertices]) for i in range(n_vertices - 1)]
        return vertices

    def generate_completely_connected_graph(self, n_vertices: int) -> list[TestV]:
        vertices = [TestV(i) for i in range(n_vertices)]
        edges = [(vertices[i], vertices[j]) for j in range(len(vertices)) for i in range(j + 1)]
        return vertices

    def generate_halfly_connected_graph(self, n_vertices: int) -> list[TestV]:
        vertices = [TestV(i) for i in range(n_vertices)]
        edges = [(vertices[i], vertices[(i + 1) % n_vertices]) for i in range(n_vertices - 1)]
        extra_edges = [(vertices[i], vertices[j]) for j in range(len(vertices)) if i != j]
        return vertices

    def generate_halfly_connected_graph_no_backtracking(self, n_vertices: int) -> list[TestV]:
        vertices = [TestV(i) for i in range(n_vertices)]
        edges = [(vertices[i], vertices[(i + 1) % n_vertices]) for i in range(n_vertices - 1)]
        extra_edges = [(vertices[i], vertices[j]) for j in range(len(vertices)) if i != j]
        return vertices

    def assert_order(self, post_order: list[TestV], v1: TestV, v2: TestV):
        index1 = [i[0] for i in enumerate(post_order) if i[1].id == str(v1.id)].index(0)
        index2 = [i[0] for i in enumerate(post_order) if i[1].id == str(v2.id)].index(0)
        self.assertLess(index1, index2)

    def assert_strong_graph(self, strongly_connected_components: list, vertices: tuple[TestV]):
        size = len(vertices)
        for component in strongly_connected_components:
            if len(component) == size:
                self.assertEqual(set(component), set(list(vertices)))
                return
        self.fail("Unexpected set size")

    @staticmethod
    def vertex(id):
        return TestV(id)

    @staticmethod
    def edge(start: TestV, end: TestV):
        e = (start, end)
        # g.addEdge(e)  # This line is commented out because it's not clear what 'g' refers to.
        return e

    @staticmethod
    def id(v):
        return v.id

    @staticmethod
    def set(vertices: tuple[TestV]):
        s = {v for v in vertices}
        return s

    def find_dominance(self, from_: TestV, algo) -> list[object]:
        dominated = algo.get_dominated(from_)
        filtered = [(edge.start, edge.end) for edge in self.graph if edge.start in dominated or edge.end in dominated]
        return filtered

    def find_post_dominance(self, from_: TestV, algo) -> list[object]:
        try:
            post_dominated = GraphAlgorithms.find_post_dominance(self.graph, from_, TaskMonitor.DUMMY)
            filtered = [(edge.start, edge.end) for edge in self.graph if edge.start in post_dominated or edge.end in post_dominated]
            return filtered
        except CancelledException as e:
            # can't happen; dummy monitor
            self.fail("Someone changed my monitor!!")
        return None

    def assert_path_exists(self, paths: list[list[TestV]], vertices: tuple[TestV]):
        expected_path = [list(vertices)]
        for path in paths:
            if path == expected_path:
                return
        self.fail(f"List of paths does not contain: {expected_path}\nactual paths: {paths}")

    @staticmethod
    def assert_list_equals_one_of(actual, *expected):
        buffy = ""
        for list_ in expected:
            if are_lists_equal(actual, list_):
                return
            buffy += str(list_) + "\n"
        self.fail(f"Expected: {buffy}\nActual: {actual}")

    @staticmethod
    def are_lists_equal(l1, l2):
        return set(map(str, l1)) == set(map(str, l2))


if __name__ == "__main__":
    unittest.main()
