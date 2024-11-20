Here is the translation of the given Java code into equivalent Python:

```Python
from collections import OrderedDict, defaultdict

class DeterministicDependencyGraph:
    def __init__(self):
        self.node_map = {}
        self.dependency_node_set = set()

    def copy(self):
        new_graph = DeterministicDependencyGraph()
        for node in self.node_map.values():
            new_graph.add_value(node['value'])
            if 'set_of_nodes_that_depend_on_me' in node:
                for child in node['set_of_nodes_that_depend_on_me']:
                    new_graph.add_dependency(child, node['value'])
        return new_graph

    def create_node_map(self):
        return defaultdict(dict)

    def create_node_set(self):
        return OrderedDict()

    def add_value(self, value):
        self.node_map[value] = {'value': value, 'set_of_nodes_that_depend_on_me': set()}

    def get_node_map_values(self):
        return list(self.node_map.keys())

    def add_dependency(self, child, parent):
        if parent in self.node_map:
            self.node_map[parent]['set_of_nodes_that_depend_on_me'].add(child)
```

Note that Python does not have direct equivalents for Java's `TreeMap` and `ListOrderedSet`, so I used the built-in `dict` (which is a hash table) to simulate the behavior of a map, and the `OrderedDict` class from the `collections` module to simulate the ordered set.