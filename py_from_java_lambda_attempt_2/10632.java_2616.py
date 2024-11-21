Here is the translation of the given Java code into Python:

```Python
import threading
from collections import defaultdict, deque

class ConcurrentGraphQTest:
    def __init__(self):
        pass

    @staticmethod
    def test():
        completion_order = []

        graph = DependencyGraph()
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
        graph.add_dependency("B1", "C2")
        graph.add_dependency("B2", "C1")
        graph.add_dependency("B3", "C2")
        graph.add_dependency("B4", "C1")

        assert not graph.has_cycles()

        saved_graph = graph.copy()

        def process_item(item):
            with lock:
                completion_order.append(item)

        pool = GThreadPool.get_private_thread_pool("ConcurrentGraphQ Test")
        queue = ConcurrentGraphQ(process_item, graph, pool)
        queue.execute()
        check_order_satisfies_dependencies(saved_graph, completion_order)


    @staticmethod
    def check_order_satisfies_dependencies(dependency_graph, visited_order):
        if len(visited_order) > dependency_graph.size():
            assert False, "More items were visited than the number of items in the graph"
        elif len(visited_order) < dependency_graph.size():
            assert False, "Not all items in the graph were visited"

        items = set(visited_order)
        if len(items) != len(visited_order):
            assert False, "duplicate item(s) in linearOrder\n"

        visited_order_map = {item: i for i, item in enumerate(visited_order)}

        for key in dependency_graph.values():
            if key not in visited_order_map:
                assert False, f"dependencyGraph key {key} not in linearOrder\n"
            dependents = dependency_graph.get_dependent_values(key)
            for dependent in dependents:
                if key == dependent:
                    assert False, f"dependencyGraph key {key} depends on itself\n"
                elif dependent not in visited_order_map:
                    assert False, f"dependent {dependent} of dependencyGraph key {key} not in linearOrder\n"
                else:
                    if visited_order_map[dependent] <= visited_order_map[key]:
                        assert False, f"dependent {dependent} of dependencyGraph key {key} came first ({visited_order_map[dependent]} < {visited_order_map[key]})\n"


class GThreadPool:
    @staticmethod
    def get_private_thread_pool(name):
        pass


class ConcurrentGraphQ:
    def __init__(self, process_item, graph, pool):
        self.process_item = process_item
        self.graph = graph
        self.pool = pool

    def execute(self):
        for item in self.graph.values():
            self.pool.apply_async(self.process_item, (item,))
```

Please note that the code above is a direct translation of your Java code into Python. It may not be perfect and might require some adjustments to work correctly with Python's syntax and semantics.