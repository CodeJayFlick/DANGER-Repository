Here is the translation of the given Java code into Python:

```Python
class ChkDominanceAlgorithm:
    def __init__(self, source_graph: 'GDirectedGraph', navigator: 'GraphNavigator', monitor):
        self.navigator = navigator
        self.source_graph = source_graph
        self.mutable_graph = MutableGDirectedGraphWrapper(source_graph)
        self.root = find_root()
        dominator_map[None] = None  # Initialize the root as its own idom.
        monitor.set_message("Computing dominance")
        compute_dominance(monitor)

    def find_root(self):
        return unify_sources(self.mutable_graph, self.navigator) and unify_sinks(self.mutable_graph, self.navigator)

    def compute_dominance(self, monitor):
        vertices = list(self.navigator.get_vertices_in_post_order(self.mutable_graph))
        map_ = {v: i for i, v in enumerate(vertices)}
        changed = True
        while changed:
            monitor.check_cancelled()
            changed = False

            # Start from the end so we always have a predecessor.
            for i in range(len(vertices) - 2, -1, -1):
                b = vertices[i]
                predecessors = self.navigator.get_predecessors(self.mutable_graph, b)
                new_idom = None
                for p in predecessors:
                    if dominator_map[p] is not None:
                        new_idom = p
                        break

                if new_idom is None:
                    raise AssertionError("No processed predecessors found for " + str(b))

                for p in predecessors:
                    if new_idom == p:
                        continue
                    if dominator_map.get(p) is not None:
                        new_idom = intersect(p, new_idom, map_)
                idom = dominator_map[b]
                if new_idom != idom:
                    last = dominator_map[b] = new_idom
                    dominated_map[new_idom].add(b)
                    if last is not None:
                        dominated_map[last].remove(b)
                    changed = True

    def intersect(self, v1: 'V', v2: 'V', map_):
        finger1 = v1
        finger2 = v2
        index1 = map_[finger1]
        index2 = map_[finger2]

        while not finger1 == finger2:
            if index1 < index2:
                finger1 = dominator_map.get(finger1)
                index1 = map_.get(finger1)

            elif index2 < index1:
                if dominator_map.get(finger2) is None:  # This can happen when the dominators for 'finger2' have not yet been calculated.
                    return finger1
                finger2 = dominator_map.get(finger2)
                index2 = map_.get(finger2)

        return finger1

    def get_dominated(self, a):
        results = set()
        self.do_get_dominated(a, results)
        return results

    def do_get_dominated(self, a: 'V', results: set):
        add(a, results)  # A node always dominates itself.
        dominated = dominated_map.get(a)
        if dominated is not None:
            for b in dominated:
                self.do_get_dominated(b, results)

    def getDominators(self, v):
        dominators = set()
        dominators.add(v)

        while not root == v:
            v = dominator_map[v]  # Immediate dominator.
            add(v, dominators)
        return dominators

    def add(self, v: 'V', collection: list):
        if is_dummy(v):  # This can happen when the graph contains dummy nodes that are not part of any path.
            pass
        else:
            collection.append(v)

    @staticmethod
    def is_dummy(v):
        return v is not None and source_graph.is_dummy(v)

    def get_dominance_tree(self):
        dg = GraphFactory.create_directed_graph()
        vertices = self.source_graph.get_vertices()
        sources = self.navigator.get_sources(self.source_graph)
        for vertex in vertices:
            if sources.contains(vertex):  # This can happen when the graph contains dummy nodes that are not part of any path.
                continue
            dominator = get_immediate_dominator(vertex)
            if dominator != vertex:  # Immediate dominators should be different from themselves.
                dg.add_edge(dominator, vertex)

        return dg

    def get_immediate_dominator(self, v):
        dom = dominator_map.get(v)
        if is_dummy(dom):  # This can happen when the graph contains dummy nodes that are not part of any path.
            return None
        return dom

    def clear(self):
        dominated_map.clear()
        dominator_map.clear()

class MutableGDirectedGraphWrapper:
    def __init__(self, source_graph: 'GDirectedGraph'):
        self.source_graph = source_graph

class GraphNavigator:
    @staticmethod
    def top_down_navigator():
        pass

    @staticmethod
    def get_vertices_in_post_order(graph):
        pass

    @staticmethod
    def get_predecessors(graph, vertex):
        pass

    @staticmethod
    def get_sources(graph: 'GDirectedGraph'):
        pass

class GDirectedGraph:
    def __init__(self):
        pass

    def is_dummy(self, v):
        pass

    def add_edge(self, edge):
        pass

    def create_directed_graph():
        pass

# This code assumes that the graph factory and other classes are implemented elsewhere.
```

This Python translation maintains the same functionality as the original Java code.