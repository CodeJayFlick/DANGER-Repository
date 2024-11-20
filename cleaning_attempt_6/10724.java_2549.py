class JohnsonCircuitsAlgorithm:
    JAVA_STACK_DEPTH_LIMIT = 2700

    def __init__(self, g, accumulator):
        self.g = g
        self.accumulator = accumulator

    def compute(self, unique_circuits, monitor):
        strongly_connected_components = GraphAlgorithms.get_strongly_connected_components(self.g)

        for component in strongly_connected_components:
            if len(component) < 2:
                continue

            sub_graph = GraphAlgorithms.create_sub_graph(self.g, component)
            vertices = list(sub_graph.vertices())

            size = len(vertices) - 1
            if unique_circuits:
                size += 1

            for i in range(size):
                start_vertex = vertices[i]

                self.blocked_set.clear()
                self.blocked_back_edges_map.clear()

                circuit(start_vertex, 0, monitor)

                if unique_circuits:
                    sub_graph.remove_vertex(start_vertex)
        return

    def circuit(self, v, depth, monitor):
        monitor.check_cancelled()

        if depth > self.JAVA_STACK_DEPTH_LIMIT:
            return False

        found_circuit = False
        self.blocked_set.add(v)
        stack = [v]
        out_edges = list(sub_graph.out_edges(v))
        for edge in out_edges:
            u = edge.end()
            if u == start_vertex:
                output_circuit()
                found_circuit = True
            elif not self.blocked_set.contains(u):
                found_circuit |= circuit(u, depth + 1, monitor)

        if found_circuit:
            unblock(v)
        else:
            for edge in out_edges:
                u = edge.end()
                add_back_edge(u, v)
        stack.pop()
        return found_circuit

    def unblock(self, v):
        self.blocked_set.remove(v)
        set = self.blocked_back_edges_map.get(v)
        if set is None:
            return
        for u in set:
            if self.blocked_set.contains(u):
                unblock(u)
        set.clear()

    def add_back_edge(self, u, v):
        set = self.blocked_back_edges_map.get(u)
        if set is None:
            set = {v}
            self.blocked_back_edges_map[u] = set
        else:
            set.add(v)

    def output_circuit(self):
        circuit = list(stack) + [start_vertex]
        self.accumulator.add(circuit)


class GraphAlgorithms:

    @staticmethod
    def get_strongly_connected_components(g):
        pass

    @staticmethod
    def create_sub_graph(g, vertices):
        pass


# Example usage:
g = ...  # Create a graph object
accumulator = Accumulator(list)  # Initialize an accumulator for storing circuits
algorithm = JohnsonCircuitsAlgorithm(g, accumulator)
algorithm.compute(unique_circuits=True, monitor=None)

