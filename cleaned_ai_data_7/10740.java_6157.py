from abc import ABCMeta, abstractmethod
import weakref
from collections import defaultdict, deque

class DefaultVisualGraph(metaclass=ABCMeta):
    def __init__(self):
        self.focused_vertex = None
        self.selected_vertices = set()
        self.change_listeners = weakref.WeakSet()

    @abstractmethod
    def copy(self):
        pass

    def set_selected_vertices(self, selected_vertices):
        self.clear_focused_vertex()
        for vertex in selected_vertices:
            vertex.set_selected(True)
        self.focused_vertex = None if not selected_vertices else next(iter(selected_vertices))
        self.selected_vertices = selected_vertices.copy()

    def clear_focused_vertex(self):
        if self.focused_vertex is not None:
            self.focused_vertex.set_focused(False)
            self.focused_vertex.set_selected(False)
            self.focused_vertex = None

    def set_vertex_focused(self, vertex, focused):
        self.clear_selected_vertices()
        vertex.set_focused(focused)
        if focused:
            vertex.set_selected(True)
            self.focused_vertex = vertex
        else:
            self.focused_vertex = None

    @property
    def focused_vertex(self):
        return self.focused_vertex

    def clear_selected_vertices(self):
        self.clear_focused_vertex()
        for vertex in list(self.selected_vertices):
            vertex.set_selected(False)
        self.selected_vertices.clear()

    @property
    def selected_vertices(self):
        if not self.selected_vertices and self.focused_vertex is None:
            return set()
        elif self.selected_vertices:
            return self.selected_vertices.copy()
        else:
            return {self.focused_vertex}

    def vertex_location_changed(self, v, point, change_type):
        pass

    def dispose(self):
        self.selected_vertices.clear()
        self.change_listeners = weakref.WeakSet()

    def initialize_location(self, v):
        if not hasattr(v, 'location'):
            return
        layout = self.get_layout()
        location = layout.apply(v)
        v.location = location

    def get_all_edges(self, v):
        in_edges = list(self.in_edges(v))
        out_edges = list(self.out_edges(v))
        concatenated = deque(list(in_edges) + list(out_edges), maxlen=len(in_edges)+len(out_edges))
        return concatenated

    def get_edges(self, start, end):
        outs = set(self.out_edges(start))
        ins = set(self.in_edges(end))
        unique = {edge for edge in (outs | ins)}
        filtered = [edge for edge in unique if edge.start == start and edge.end == end]
        return filtered

    def add_vertex(self, v):
        added = super().add_vertex(v)
        if added:
            self.initialize_location(v)
            vertices_added([v])
        return added

    def add_edge(self, edge, endpoints, edge_type):
        added = super().add_edge(edge, endpoints, edge_type)
        if added:
            edges_added([edge])
        return added

    def remove_vertex(self, v):
        removed = super().remove_vertex(v)
        if removed:
            vertices_removed([v])
        return removed

    def remove_vertices(self, to_remove):
        for vertex in to_remove:
            self.remove_vertex(vertex)

    def remove_edge(self, edge):
        removed = super().remove_edge(edge)
        if removed:
            edges_removed([edge])
        return removed

    def add_graph_change_listener(self, l):
        self.change_listeners.add(l)

    def remove_graph_change_listener(self, l):
        self.change_listeners.remove(l)


class VisualGraph(DefaultVisualGraph):
    pass
