class FunctionEdgeCache:
    def __init__(self):
        self.all_edges_by_function = {}
        self.tracked = set()

    def get(self, f):
        return self.all_edges_by_function.get(f)

    def is_tracked(self, f):
        return f in self.tracked

    def set_tracked(self, f):
        self.tracked.add(f)
