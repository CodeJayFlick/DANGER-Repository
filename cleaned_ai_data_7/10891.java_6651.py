import unittest
from collections import deque, defaultdict
from heapq import heappop, heappush

class TestEdge:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end


class WeightedTestEdge(TestEdge):
    def __init__(self, start, end, weight):
        super().__init__(start, end)
        self.weight = weight

    def get_weight(self):
        return self.weight


class TestGImplicitDirectedGraph:
    pass


def construct_three_graph_unweighted():
    graph = defaultdict(dict)
    for vertex in ["A", "B", "C"]:
        graph[vertex] = {}
    edges = [
        {"start": "A", "end": "B"},
        {"start": "B", "end": "C"},
        {"start": "A", "end": "C"}
    ]
    for edge in edges:
        graph[edge["start"]][edge["end"]] = None
        graph[edge["end"]][edge["start"]] = None


def construct_three_graph_weighted():
    graph = defaultdict(dict)
    for vertex in ["A", "B", "C"]:
        graph[vertex] = {}
    edges = [
        {"start": "A", "end": "B", "weight": 1},
        {"start": "B", "end": "C", "weight": 1},
        {"start": "A", "end": "C", "weight": 2}
    ]
    for edge in edges:
        graph[edge["start"]][edge["end"]] = edge["weight"]
        graph[edge["end"]][edge["start"]] = None


def make_paths(paths):
    result = []
    for path in paths:
        p = deque()
        for e in path:
            p.append(e)
        result.append(p)
    return result


class TestDijkstraShortestPathsAlgorithm(unittest.TestCase):

    def test_explicit_graph_no_max_unit(self):
        construct_three_graph_unweighted()
        dijkstra = DijkstraShortestPathsAlgorithm(graph, GEdgeWeightMetric.unit_metric())
        self.assertEqual(make_paths([{"start": "A", "end": "C"}]), dijkstra.compute_optimal_paths("A", "C"))
        self.assertEqual([], dijkstra.compute_optimal_paths("C", "A"))

    def test_unweighted_no_metric_error(self):
        construct_three_graph_unweighted()
        with self.assertRaises(ClassCastException):
            DijkstraShortestPathsAlgorithm(graph).compute_optimal_paths("A", "C")

    def test_explicit_weighted_multiple(self):
        construct_three_graph_weighted()
        dijkstra = DijkstraShortestPathsAlgorithm(graph)
        self.assertEqual(make_paths([{"start": "A", "end": "B"}, {"start": "B", "end": "C"}]), 
                         dijkstra.compute_optimal_paths("A", "C"))

    def test_explicit_weighted_max(self):
        construct_three_graph_weighted()
        dijkstra = DijkstraShortestPathsAlgorithm(graph, 1.0)
        self.assertEqual([], dijkstra.compute_optimal_paths("A", "B"))
        self.assertEqual([{"start": "B", "end": "C"}], 
                         dijkstra.compute_optimal_paths("B", "C"))
        self.assertEqual([], dijkstra.compute_optimal_paths("C", "A"))


class CollatzEdge:
    def __init__(self, start, op, end):
        self.start = start
        self.end = end
        self.op = op

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def __str__(self):
        return f"{self.op.name()}({self.start})={self.end}"

    def __eq__(self, other):
        if isinstance(other, CollatzEdge):
            return str(self) == str(other)
        else:
            return False


class CollatzGraph:
    def get_in_edges(self, v):
        raise NotImplementedError

    def get_out_edges(self, v):
        result = []
        r = v * 2
        if r >= 0:
            result.append(CollatzEdge(v, "INV_DIV2", r))
        r = v ** 2
        if r >= 0:
            result.append(CollatzEdge(v, "SQR", r))
        r = v - 1
        if r % 3 == 0:
            result.append(CollatzEdge(v, "INV_MUL3_ADD1", r // 3))
        return result

    def copy(self):
        raise NotImplementedError


def make_collatz_paths(start, paths):
    result = []
    cur = start
    p = deque()
    for op in paths:
        next_ = None
        if op == "INV_DIV2":
            next_ = cur * 2
        elif op == "SQR":
            next_ = cur ** 2
        elif op == "INV_MUL3_ADD1":
            next_ = (cur - 1) // 3
        p.append(CollatzEdge(cur, op, next_))
        cur = next_
    result.append(p)
    return result


class TestDijkstraShortestPathsAlgorithmCollatz(unittest.TestCase):

    def test_implicit(self):
        dijkstra = DijkstraShortestPathsAlgorithm(new CollatzGraph(), 10.0, GEdgeWeightMetric.unit_metric())
        opt = dijkstra.compute_optimal_paths(1, 10)
        exp = make_collatz_paths(
            1,
            ["INV_DIV2", "INV_DIV2", "SQR", "INV_MUL3_ADD1", "INV_DIV2"]
        )
        self.assertEqual(exp, list(opt))


if __name__ == "__main__":
    unittest.main()
