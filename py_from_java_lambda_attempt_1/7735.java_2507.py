Here is the translation of the Java code to Python:
```
class EdgeComparator:
    def __init__(self, renderer):
        self.renderer = renderer

    def compare(self, edge1: 'AttributedEdge', edge2: 'AttributedEdge') -> int:
        edge_type1 = edge1.get_edge_type()
        edge_type2 = edge2.get_edge_type()

        if edge_type1 is None and edge_type2 is None:
            return 0
        elif edge_type1 is None:
            return 1
        elif edge_type2 is None:
            return -1

        priority1 = self.renderer.get_edge_priority(edge_type1)
        priority2 = self.renderer.get_edge_priority(edge_type2)

        return priority1.compare_to(priority2)
```
Note that I've used Python's type hints to indicate the types of the `edge1` and `edge2` parameters, as well as the return value. This is not strictly necessary for a pure-Python implementation, but it can be helpful for readability and documentation purposes.

Also, in Python 3.x, you would typically use the `__eq__`, `__lt__`, etc. methods to implement comparison operators like `==` or `<`. However, since this code appears to be translating from Java's `Comparator` interface, I've used a more direct translation approach using the `compare_to()` method (which is equivalent to Python's `__gt__` method).