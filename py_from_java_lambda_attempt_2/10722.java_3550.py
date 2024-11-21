Here is the translation of the given Java code into Python:

```Python
class GraphNavigator:
    def __init__(self, is_top_down):
        self.is_top_down = is_top_down

    @staticmethod
    def top_down_navigator():
        return GraphNavigator(True)

    @staticmethod
    def bottom_up_navigator():
        return GraphNavigator(False)

    def get_edges(self, graph, v):
        if self.is_top_down:
            return list(graph.out_edges(v))
        else:
            return list(graph.in_edges(v))

    def is_top_down_traversal(self):
        return self.is_top_down

    def get_successors(self, graph, v):
        if self.is_top_down:
            return list(graph.successors(v))
        else:
            return list(graph.predecessors(v))

    def get_predecessors(self, graph, v):
        if self.is_top_down:
            return list(graph.predecessors(v))
        else:
            return list(graph.successors(v))

    def get_end(self, e):
        if self.is_top_down:
            return e.end
        else:
            return e.start

    @staticmethod
    def get_sources(graph):
        return set([v for v in graph.vertices()])

    @staticmethod
    def get_sinks(graph):
        return set([v for v in graph.vertices()])

    def get_vertices_in_post_order(self, graph):
        if self.is_top_down:
            return list(GraphAlgorithms.get_vertices_in_post_order(graph))
        else:
            return list(reversed(list(GraphAlgorithms.get_vertices_in_post_order(graph))))
```

Please note that this is a direct translation of the given Java code into Python.