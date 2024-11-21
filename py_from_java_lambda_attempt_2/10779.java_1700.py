Here's your Java code translated into Python:

```Python
class ArticulatedEdgeRouter(VirtualVertex, VirtualEdge):
    def __init__(self, viewer: VisualizationServer[V, E], edges: Collection[E]):
        super().__init__()
        self.viewer = viewer
        self.edges = edges

    def route(self) -> None:
        debug_counter.set(debug_counter.incrementAndGet())

        layout = self.viewer.get_graph_layout()
        graph = layout.get_graph()

        for edge in self.edges:
            if not is_occluded(edge):
                continue

            start, end = graph.get_endpoints(edge)
            routed_shape = create_routed_two_point_shape(start, end, edge)

            debug_shape = DebugShape(self.viewer, debug_counter, "Left Edge", routed_shape,
                                      get_routing_box_color(edge))
            self.viewer.add_post_render_paintable(debug_shape)

    def constrict_to_vertices_inside_shape(self, bounding_shape: Shape, start: V, end: E) -> None:
        vertices = set()
        vertex_bounds_map = self.get_vertex_bounds()

        for entry in vertex_bounds_map.items():
            v, bounds = entry
            if bounding_shape.intersects(bounds):
                vertices.add(v)

        return get_bounds_for_vertices_in_layout_space(self.viewer, vertices)

    def create_rectangle(self, start_point: Point2D, end_point: Point2D) -> Rectangle:
        smallest_x = min(start_point.x, end_point.x)
        smallest_y = min(start_point.y, end_point.y)
        largest_x = max(start_point.x, end_point.x)
        largest_y = max(start_point.y, end_point.y)

        width = int(largest_x - smallest_x)
        height = int(largest_y - smallest_y)

        return Rectangle(int(smallest_x), int(smallest_y), width, height)

    def move_articulations_around_vertices(self, vertices: set, edge: E, go_left: bool) -> None:
        layout = self.viewer.get_graph_layout()
        graph = layout.get_graph()

        start, end = graph.get_endpoints(edge)
        point1 = Point2D(int(start_point.x), int(start_point.y))
        point2 = Point2D(int(end_point.x), int(end_point.y))

        if go_left:
            x = bounds.x - 20
        else:
            x = bounds.x + bounds.width + 20

        top = Point2D(x, bounds.y - 20)
        bottom = Point2D(x, bounds.y + bounds.height + 20)

        articulation_points = [top, bottom]

        edge.set_articulations(articulation_points)

    def create_routed_two_point_shape(self, start: V, end: E, go_left: bool) -> Shape:
        edges_set = set()
        edges_set.add(edge)
        occluded_edges_map = self.get_occluded_edges(edges_set)

        intersecting_vertices = occluded_edges_map.get(edge)

        if not intersecting_vertices:
            return create_line_edge(start, end, edge)

        new_edge = E.clone_edge(start, end)
        move_articulations_around_vertices(intersecting_vertices, new_edge, go_left)

        return get_edge_shape_in_graph_space(self.viewer, new_edge)

    def get_occluded_edges(self, edges_set: set) -> dict:
        layout = self.viewer.get_graph_layout()
        graph = layout.get_graph()

        vertices = list(graph.vertices())

        map = {}
        for v in vertices:
            vertex_bounds = get_vertex_bounds_in_graph_space(self.viewer, v)
            if edge.intersects(vertex_bounds):
                set_.add(v)

    def get_vertex_bounds(self) -> dict:
        if self.cached_vertex_bounds_map is not None:
            return self.cached_vertex_bounds_map

        layout = self.viewer.get_graph_layout()
        graph = layout.get_graph()

        vertices = list(graph.vertices())

        map = {}
        for v in vertices:
            vertex_bounds = get_vertex_bounds_in_graph_space(self.viewer, v)
            map[v] = vertex_bounds
        self.cached_vertex_bounds_map = map

    def get_articulations(self, shape: Shape) -> list:
        path_iterator = shape.get_path_iterator()
        articulations = []

        while True:
            try:
                coords = [0.0 for _ in range(6)]
                path_iterator.next()
                path_iterator.current_segment(coords)
                point = Point2D(float(coords[0]), float(coords[1]))
                layout_space_point = translate_point_from_graph_space_to_layout_space(point, self.viewer)

                articulations.append(layout_space_point)
            except StopIteration:
                break

        return articulations
```

Please note that this is a direct translation of your Java code into Python. It might not be the most idiomatic or efficient way to write Python code, but it should work as expected.