Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import collections
import math

class AbstractGroupingFunctionGraphJob(metaclass=ABCMeta):
    def __init__(self, controller, group_vertex, new_vertices, vertices_to_remove, relayout_override, use_animation):
        super().__init__()
        self.controller = controller
        self.group_vertex = group_vertex
        self.new_vertices = set(new_vertices)
        self.vertices_to_remove = set(vertices_to_remove)

    def finished(self):
        super().finished()
        self.notify_group_change()

        for vertex in self.get_new_vertices():
            self.viewer.picked_vertex_state.pick(vertex, True)

        self.get_vertices_to_be_removed().clear()
        self.get_new_vertices().clear()

    @abstractmethod
    def notify_group_change(self):
        pass

    def update_destination_locations(self):
        ignore = set(self.get_vertices_to_remove())
        positions = None

        if self.relayout:
            positions = self.calculate_default_layout_locations(ignore)
            locations = positions.vertex_locations()
            group_destination_point = maybe_get_group_destination_point(locations)

            if group_destination_point is not None:
                locations[self.group_vertex] = group_destination_point
        else:
            positions = self.get_current_layout_locations()

        layout_locations = positions.vertex_locations()
        grouping_destination_locations = self.get_grouping_destination_locations(self.relayout, group_destination_point)
        
        for entry in grouping_destination_locations.items():
            vertex, location = entry
            if vertex not in ignore:
                layout_locations[vertex] = location

        return positions

    @abstractmethod
    def get_grouping_destination_locations(self, is_relayment, group_vertex_destination_location):
        pass

    def get_vertices_to_move(self):
        graph_vertices = self.graph.get_vertices()
        
        if self.relayout:
            return set(graph_vertices)
        else:
            vertices = set(self.group_vertex.get_vertices())
            
            # this needs to be in intersection of group vertices with those still in the graph, as the
            # group vertices may no longer be in the graph, such as when adding to an existing group
            vertices &= graph_vertices
            
            return vertices

    def get_vertices_to_be_removed(self):
        return self.vertices_to_remove

    def get_new_vertices(self):
        return set(self.new_vertices)

    @abstractmethod
    def update_opacity(self, percent_complete):
        pass

    def clear_location_cache(self):
        self.viewer.graph_layout.clear()

class GroupingFunctionGraphJob(AbstractGroupingFunctionGraphJob):

    def __init__(self, controller, group_vertex, new_vertices, vertices_to_remove, relayout_override, use_animation):
        super().__init__(controller, group_vertex, new_vertices, vertices_to_remove, relayout_override, use_animation)

    @abstractmethod
    def notify_group_change(self):
        pass

    # Private Methods
    def remove_old_vertex_and_edges(self):
        for vertex in self.get_vertices_to_be_removed():
            self.graph.remove_vertex(vertex)
            
    def maybe_get_group_destination_point(self, locations):
        to_remove = set(self.get_vertices_to_remove())
        
        if not to_remove or group_vertex not in to_remove:
            return None
        
        # We want the group vertex to fade away into another vertex.  We also want to be 
        # consistent, so just merge to the root vertex of the group vertex.
        address = self.group_vertex.get_vertex_address()
        
        for vertex in self.group_vertex.get_vertices():
            if vertex.contains_address(address):
                return locations[self.new_vertices.pop()]
                
    def calculate_default_layout_locations(self, ignore):
        pass

    def get_current_layout_locations(self):
        pass
```

Note: This is a direct translation of the Java code into Python. The actual implementation may vary depending on how you want to implement certain methods and classes in your specific use case.