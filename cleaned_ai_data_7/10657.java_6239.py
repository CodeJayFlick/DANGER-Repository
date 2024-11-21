import unittest
from collections import defaultdict, deque

class AbstractDependencyGraph:
    def __init__(self):
        self.graph = defaultdict(list)

    def add_dependency(self, from_node, to_node):
        self.graph[from_node].append(to_node)

    def get_unvisited_independent_values(self):
        unvisited_nodes = set()
        for node in self.graph:
            if not any(neighbor == node for neighbor in self.graph[neighbor]):
                unvisited_nodes.add(node)
        return unvisited_nodes

    def remove(self, node):
        del self.graph[node]

    def pop(self):
        visited_node = None
        queue = deque([node for node in self.graph])
        while queue:
            node = queue.popleft()
            if not any(neighbor == node for neighbor in self.graph[neighbor]):
                visited_node = node
                break
        return visited_node

    def has_cycles(self):
        visited_nodes = set()

        def dfs(node, parent=None):
            nonlocal visited_nodes
            visited_nodes.add(node)
            for neighbor in self.graph[node]:
                if neighbor not in visited_nodes:
                    if dfs(neighbor, node):
                        return True
                elif neighbor != parent:
                    return True
            return False

        for node in self.graph:
            if node not in visited_nodes and dfs(node):
                return True
        return False


class DependencyGraphTest(unittest.TestCase):

    def test_simple_case_dependency_graph(self):
        graph = AbstractDependencyGraph()
        run_simple_case(graph)

    def test_multiple_dependency_case_dependency_graph(self):
        graph = AbstractDependencyGraph()
        run_multiple_dependency_case(graph)

    def test_pop_dependency_graph(self):
        graph = AbstractDependencyGraph()
        run_pop(graph)

    def test_pop_with_cycle_dependency_graph(self):
        graph = AbstractDependencyGraph()
        run_pop_with_cycle(graph)

    def test_cycle_detection_dependency_graph(self):
        graph = AbstractDependencyGraph()
        run_cycle_detection(graph)

    def test_cycle_detection_does_not_corrupt_graph_dependency_graph(self):
        graph = AbstractDependencyGraph()
        run_cycle_detection_does_not_corrupt_graph(graph)

    def test_random_processing_of_dependencies_simulation_dependency_graph(self):
        graph = AbstractDependencyGraph()
        run_random_processing_of_dependencies_simulation(graph)


def run_simple_case(graph):
    graph.add_dependency(1, 2)
    graph.add_dependency(2, 3)
    graph.add_dependency(3, 4)

    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(4 in unvisited_nodes)

    graph.remove(4)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(3 in unvisited_nodes)

    graph.remove(3)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(2 in unvisited_nodes)

    graph.remove(2)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(1 in unvisited_nodes)

    graph.remove(1)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertFalse(unvisited_nodes)


def run_multiple_dependency_case(graph):
    graph.add_dependency(1, 2)
    graph.add_dependency(2, 3)
    graph.add_dependency(1, 3)

    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(3 in unvisited_nodes)

    graph.remove(3)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(2 in unvisited_nodes)

    graph.remove(2)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(1 in unvisited_nodes)

    graph.remove(1)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertFalse(unvisited_nodes)


def run_pop(graph):
    graph.add_dependency(1, 2)
    graph.add_dependency(2, 3)
    graph.add_dependency(3, 4)

    for _ in range(len(graph.graph)):
        visited_node = graph.pop()
        self.assertEqual(4, int(visited_node))
        self.assertEqual(3, int(graph.pop()))
        self.assertEqual(2, int(graph.pop()))
        self.assertEqual(1, int(graph.pop()))

    self.assertIsNone(graph.pop())


def run_pop_with_cycle(graph):
    graph.add_dependency(1, 2)
    graph.add_dependency(2, 3)
    graph.add_dependency(3, 4)
    graph.add_dependency(2, 1)

    try:
        while not graph.is_empty():
            graph.pop()
        self.fail("Expected cycle exception")
    except IllegalStateException:
        pass


def run_cycle_detection(graph):
    graph.add_dependency(1, 2)
    graph.add_dependency(2, 3)
    graph.add_dependency(3, 4)

    self.assertFalse(graph.has_cycles())

    graph.add_dependency(4, 1)
    self.assertTrue(graph.has_cycles())


def run_cycle_detection_does_not_corrupt_graph(graph):
    graph.add_dependency(1, 2)
    graph.add_dependency(2, 3)
    graph.add_dependency(3, 4)

    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(4 in unvisited_nodes)

    graph.remove(4)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(3 in unvisited_nodes)

    graph.remove(3)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(2 in unvisited_nodes)

    graph.remove(2)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertEqual(len(unvisited_nodes), 1)
    self.assertTrue(1 in unvisited_nodes)

    graph.remove(1)
    unvisited_nodes = graph.get_unvisited_independent_values()
    self.assertFalse(unvisited_nodes)


def run_random_processing_of_dependencies_simulation(graph):
    completion_order = []

    graph.add_dependency("@0", "A8")
    graph.add_dependency("@1", "A1")
    graph.add_dependency("@2", "A7")
    graph.add_dependency("@3", "A2")
    graph.add_dependency("@4", "A3")
    graph.add_dependency("@5", "A3")
    graph.add_dependency("@6", "A4")
    graph.add_dependency("@7", "A4")
    graph.add_dependency("@A", "A5")
    graph.add_dependency("@B", "A5")
    graph.add_dependency("@C", "A6")
    graph.add_dependency("@D", "A6")
    graph.add_dependency("@E", "A7")
    graph.add_dependency("@F", "A2")
    graph.add_dependency("@G", "A8")
    graph.add_dependency("@H", "A1")

    graph.add_dependency("A1", "B4")
    graph.add_dependency("A2", "B1")
    graph.add_dependency("A3", "B2")
    graph.add_dependency("A4", "B2")
    graph.add_dependency("A5", "B3")
    graph.add_dependency("A6", "B3")
    graph.add_dependency("A7", "B4")
    graph.add_dependency("A8", "B1")

    self.assertFalse(graph.has_cycles())

    while not graph.is_empty():
        visited_node = graph.pop()
        completion_order.append(visited_node)

    check_order_satisfies_dependencies(graph, completion_order)


def check_order_satisfies_dependencies(dependency_graph, visited_order):
    if len(visited_order) > dependency_graph.size:
        self.fail("More items were visited than the number of items in the graph")
    if len(visited_order) < dependency_graph.size:
        self.fail("Not all items in the graph were visited")

    items = set()
    for node in visited_order:
        items.add(node)

    if len(items) != len(visited_order):
        self.fail("duplicate item(s) in linearOrder\n")

    visited_order_map = {}
    for i, node in enumerate(visited_order):
        visited_order_map[node] = i

    for key in dependency_graph.graph:
        visited_node = visited_order_map.get(key)
        if visited_node is None:
            self.fail(f"dependencyGraph key {key} not in linearOrder\n")

        dependents = dependency_graph.graph[key]
        for dependent in dependents:
            if key == dependent:
                self.fail(f"dependencyGraph key {key} depends on itself\n")
            dependent_visited_node = visited_order_map.get(dependent)
            if dependent_visited_node is None:
                self.fail(f"dependent {dependent} of dependencyGraph key {key} not in linearOrder\n")
            if dependent_visited_node <= visited_node:
                self.fail(f"dependent {dependent} of dependencyGraph key {key} came first ({dependent_visited_node} < {visited_node})\n")


if __name__ == '__main__':
    unittest.main()
