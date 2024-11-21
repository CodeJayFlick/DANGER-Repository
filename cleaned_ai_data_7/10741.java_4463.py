class FilteringVisualGraph:
    def __init__(self):
        self.complete_graph = {}
        self.internal_call_count = 0

    def filter_vertices(self, vertices_to_filter):
        for vertex in vertices_to_filter:
            if vertex not in self.complete_graph['vertices']:
                continue
            self.remove_vertex_from_view(vertex)

    def filter_edges(self, edges_to_filter):
        for edge in edges_to_filter:
            if edge not in self.complete_graph['edges']:
                continue
            self.remove_edge_from_view(edge)

    def unfilter_vertices(self, vertices_to_unfilter):
        maybe_restore_vertices(vertices_to_unfilter)
        maybe_restore_related_edges(vertices_to_unfilter)

    def unfilter_edges(self, edges_to_unfilter):
        for edge in edges_to_unfilter:
            if edge not in self.complete_graph['edges']:
                continue
            start_vertex = edge[0]
            end_vertex = edge[1]

            # only add the edge if both vertices are in the graph
            if start_vertex in self and end_vertex in self:
                maybe_restore_edges([edge])

    def get_all_vertices(self):
        return iter(self.complete_graph['vertices'])

    def get_all_edges(self):
        return iter(self.complete_graph['edges'])

    def get_filtered_vertices(self):
        is_filtered = lambda v: not (v in self) and v in self.complete_graph['vertices']
        return filter(is_filtered, self.get_all_vertices())

    def get_filtered_edges(self):
        is_filtered = lambda e: not (e[0] in self or e[1] in self) and e in self.complete_graph['edges']
        return filter(is_filtered, self.get_all_edges())

    def get_unfiltered_vertices(self):
        return iter(self)

    def get_unfiltered_edges(self):
        return iter(self)

    def is_filtered(self):
        if len(self.complete_graph['vertices']) != len(self):
            return True
        if len(self.complete_graph['edges']) != len(self):
            return True
        return False

    def clear_filter(self):
        self.clear()
        restore_all_vertices()

    def get_reachable_vertices(self, source_vertices):
        related_edges = set()
        for vertex in source_vertices:
            related_edges.update(get_edges_from(vertex))
        return {vertex: 1 for edge in related_edges}

    def get_connected_edges(self, vertices):
        connected_edges = set()
        for vertex in vertices:
            if vertex not in self.complete_graph['vertices']:
                continue
            edges = non_null(self.complete_graph.get_incident_edges(vertex))
            connected_edges.update(edges)
        return connected_edges

    # Private Methods
    def restore_all_vertices(self):
        all_vertices = list(self.complete_graph['vertices'])
        perform_internal_update(lambda: add_vertices(all_vertices))

    def maybe_restore_vertices(self, vertices_to_restore):
        for vertex in vertices_to_restore:
            if not self.complete_graph['vertices'].get(vertex):
                continue
            perform_internal_update(lambda: super().add_vertex(vertex))

    def restore_all_edges(self):
        all_edges = list(self.complete_graph['edges'])
        perform_internal_update(lambda: add_edges(all_edges))

    def maybe_restore_edges(self, edges_to_unfilter):
        for edge in edges_to_unfilter:
            if not self.complete_graph['edges'].get(edge):
                continue
            start_vertex = edge[0]
            end_vertex = edge[1]

            # only add the edge if both vertices are in the graph
            if start_vertex in self and end_vertex in self:
                perform_internal_update(lambda: super().add_edge(edge))

    def remove_vertex_from_view(self, vertex):
        perform_internal_update(lambda: super().remove_vertex(vertex))
        maybe_remove_related_edges([vertex])

    def remove_edge_from_view(self, edge):
        perform_internal_update(lambda: super().remove_edge(edge))
        maybe_remove_connected_edges([edge[0], edge[1]])

    # Overridden Methods
    def add_vertex(self, vertex):
        if self.is_filtered():
            return False
        else:
            perform_internal_update(lambda: super().add_vertex(vertex))
            return True

    def remove_vertices(self, vertices_to_remove):
        for vertex in vertices_to_remove:
            if not (vertex in self and vertex in self.complete_graph['vertices']):
                continue
            maybe_perform_remove(lambda: complete_graph.remove_vertex(vertex))

    # Private Helper Methods
    def perform_internal_update(self, callback):
        global internal_call_count
        try:
            callback()
        finally:
            internal_call_count -= 1

    def is_internal_update(self):
        return self.internal_call_count > 0

    def maybe_perform_remove(self, callback):
        if not (self.is_filtered() and self.is_internal_update()):
            perform_internal_update(callback)

    # Inner Classes
class UnfilteredGraph:
    pass
