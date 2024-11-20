Here is a translation of the Java code into equivalent Python:

```Python
from collections import defaultdict, set

class InitializeCircuitsRunnable:
    def __init__(self, view: 'VisualGraphView', graph):
        self.view = view
        self.graph = graph
        self.all_circuit_results = set()
        self.circuit_flow_results = defaultdict(set)

    def monitored_run(self, monitor):
        monitor.set_message("Finding all loops")

        strongs = GraphAlgorithms.get_strongly_connected_components(graph)
        
        for vertices in strongs:
            if len(vertices) == 1:
                continue

            sub_graph = GraphAlgorithms.create_sub_graph(graph, vertices)

            edges = set(sub_graph.edges())
            self.all_circuit_results.update(edges)

            sub_vertices = sub_graph.vertices()
            for v in sub_vertices:
                self.circuit_flow_results[v].update(edges)
        return


    def swing_run(self):
        # TODO delete this class...now!
#         viewer = view.get_primary_graph_viewer()
#         path_highlighter = viewer.path_highlighter
#         path_highlighter.set_edge_circuits(all_circuit_results, circuit_flow_results)
#         self.view.repaint()

```

Please note that Python does not support generics like Java. The `VisualGraphView`, `VisualVertex`, `VisualEdge` and other classes are also missing in this translation as they were not provided with the original code.