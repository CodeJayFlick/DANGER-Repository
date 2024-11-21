class DepthFirstSorter:
    def __init__(self, g: 'GDirectedGraph', navigator: 'GraphNavigator'):
        self.g = g
        self.navigator = navigator
        vertex_count = len(g.get_vertices())
        self.visited = set()

    @staticmethod
    def post_order(g: 'GDirectedGraph') -> list:
        return DepthFirstSorter.post_order(g, GraphNavigator.top_downavigator())

    @staticmethod
    def post_order(g: 'GDirectedGraph', navigator: 'GraphNavigator') -> list:
        sorter = DepthFirstSorter(g, navigator)
        result = sorter.get_vertices_post_order()
        sorter.dispose()
        return result

    @staticmethod
    def pre_order(g: 'GDirectedGraph') -> list:
        return DepthFirstSorter.pre_order(g, GraphNavigator.top_downavigator())

    @staticmethod
    def pre_order(g: 'GDirectedGraph', navigator: 'GraphNavigator') -> list:
        sorter = DepthFirstSorter(g, navigator)
        result = sorter.get_vertices_pre_order()
        sorter.dispose()
        return result

    def get_vertices_post_order(self) -> list:
        seeds = self.navigator.get_sources(self.g)
        for v in seeds:
            self.post_order_visit(v)

        for v in self.g.get_vertices():
            if not self.visited.__contains__(v):
                self.post_order_visit(v)

        return list(self.visited)

    def get_vertices_pre_order(self) -> list:
        seeds = GraphAlgorithms.get_sources(self.g)
        for v in seeds:
            self.pre_order_visit(v)

        for v in self.g.get_vertices():
            if not self.visited.__contains__(v):
                self.pre_order_visit(v)

        return list(self.visited)

    def post_order_visit(self, v: 'V') -> None:
        if self.visited.__contains__(v):
            return

        self.visited.add(v)
        successors = self.navigator.get_successors(self.g, v)
        for child in successors:
            self.post_order_visit(child)

        # remove/put back here to update traversal order to be post-order
        self.visited.remove(v)
        self.visited.add(v)

    def pre_order_visit(self, v: 'V') -> None:
        if self.visited.__contains__(v):
            return

        self.visited.add(v)
        successors = self.navigator.get_successors(self.g, v)
        for child in successors:
            self.pre_order_visit(child)

    def dispose(self) -> None:
        self.visited.clear()
