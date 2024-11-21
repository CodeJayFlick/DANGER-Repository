Here is the translation of the given Java code into Python:

```Python
class TopologicalSorter:
    def __init__(self, graph: dict, require_total: bool):
        self.graph = graph
        self.require_total = require_total
        self.list = []
        self.unmarked = list(graph.keys())

    def sort(self) -> list:
        if self.require_total:
            self.check_total()
        while True:
            n = next((v for v in self.unmarked), None)
            if n is None:  # Will also cause future calls to sort() to short-circuit
                return self.list

            self.visit(n)

    def check_total(self) -> None:
        dijkstra = DijkstraShortestPathsAlgorithm(self.graph, GEdgeWeightMetric.unit_metric())
        for v1 in self.graph.keys():
            for v2 in self.graph.keys():  # Maybe look into spliterator? to avoid double check
                dist_f = dijkstra.get_distances_from_source(v1).get(v2)
                dist_r = dijkstra.get_distances_from_source(v2).get(v1)
                if dist_f is None and dist_r is None:
                    raise SorterException("Not a total order", v1, v2)

    def visit(self, n: str) -> None:
        self.visit(n, [])

    def visit(self, n: str, temp: list) -> None:
        if n in temp:
            raise SorterException("Graph is cyclic", temp)
        if n in self.unmarked:
            temp.append(n)
            try:
                for m in self.graph.get_successors(n):
                    self.visit(m, temp)
                self.unmarked.remove(n)
            finally:
                temp.pop()
            self.list.insert(0, n)


class DijkstraShortestPathsAlgorithm:
    def __init__(self, graph: dict, metric: object):
        pass

    def get_distances_from_source(self, source: str) -> dict:
        pass


class GEdgeWeightMetric:
    @staticmethod
    def unit_metric():
        return "unit"


class SorterException(Exception):
    pass
```

Note that I've replaced the Java-specific classes and methods with their Python equivalents.