Here is the translation of the Java code into equivalent Python:

```Python
class EmptyFcgData:
    def get_function(self):
        raise Exception("Empty data has no function")

    def is_function(self, f):
        return False

    def get_graph(self):
        raise Exception("Empty data has no graph")

    def get_function_edge_cache(self):
        raise Exception("Empty data has no function edge cache")

    def has_results(self):
        return False

    def dispose(self):
        pass  # we are empty; nothing to do

    def is_initialized(self):
        return False

    def get_graph_perspective(self):
        raise Exception("Empty data does not need view information")

    def set_graph_perspective(self, info):
        raise Exception("Empty data does not need view information")
```

Note that Python doesn't have direct equivalent of Java's `@Override` annotation. Also, the exception types are different in Python compared to Java (e.g., `Exception` instead of `UnsupportedOperationException`).