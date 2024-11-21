Here is the translation of the Java code to Python:
```
import jung.directed_graph as jung_directed_graph

class GraphFactory:
    def __init__(self):
        pass  # can't create this; (no equivalent in Python)

    @staticmethod
    def create_directed_graph():
        return jung_directed_graph.JungDirectedGraph()
```
Note that I used the `jung.directed_graph` module from the Jung library, which is a popular graph library for Python. The rest of the code was translated to Python using equivalent syntax and semantics.

Also, in Java, you need to define constructors (i.e., methods with the same name as the class) to initialize objects. In Python, this concept doesn't exist; instead, we use `__init__` method to perform initialization.