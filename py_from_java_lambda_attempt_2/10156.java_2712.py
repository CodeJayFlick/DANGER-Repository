Here is a translation of the Java code into equivalent Python:

```Python
import threading
from collections import deque

class ConcurrentGraphQ:
    def __init__(self, runnable, graph):
        self.graph = graph
        self.queue = deque()

    def execute(self):
        values = set(graph.get_unvisited_independent_values())
        self.queue.append(values)
        while len(self.queue) > 0 and not self.queue[0].empty():
            pass

    def dispose(self):
        if len(self.queue) > 0:
            for q in list(self.queue):
                q.empty()

class MyItemListener:
    def __init__(self, graph):
        self.graph = graph

    def item_processed(self, result):
        self.graph.remove(result.item)
        values = set(graph.get_unvisited_independent_values())
        self.queue.append(values)

# usage
graph = # your abstract dependency graph implementation here
runnable = # your runnable implementation here
concurrent_graph_q = ConcurrentGraphQ(runnable, graph)
concurrent_graph_q.execute()
```

Please note that Python does not have direct equivalent of Java's AbstractDependencyGraph and QRunnable. So I've left them as placeholder comments in the code above. You would need to implement these classes yourself based on your specific requirements.

Also, Python doesn't support generics like Java does.