Here is the translation of the Java code into Python:

```Python
import math

class MergeVertexFunctionGraphJob:
    def __init__(self, controller, viewer, merged_vertex, parent_vertex, child_vertex, use_animation):
        self.controller = controller
        self.viewer = viewer
        self.merged_vertex = merged_vertex
        self.parent_vertex = parent_vertex
        self.child_vertex = child_vertex
        self.use_animation = use_animation
        self.graph_layout = viewer.get_graph_layout()

    def can_shortcut(self):
        return False

    def shortcut(self):
        raise UnsupportedOperationException("Cannot cancel this job: " + str(self))

    def create_animator(self):
        initialize_vertex_locations()
        
        if not self.use_animation:
            return None
        
        animator = PropertySetter.create_animator(1500, self, 'percent_complete', 0.0, 1.0)
        animator.set_acceleration(0.0)
        animator.set_deceleration(0.8)
        return animator

    def finished(self):
        if is_shortcut:
            initialize_vertex_locations()
        
        clear_location_cache()
        graph_layout.set_location(merged_vertex, merged_destination)
        remove_old_vertex_and_edges()

        update_opacity(1.0)

        controller.synchronize_program_location_after_edit()
        viewer.repaint()

    def set_percent_complete(self, percent_complete):
        update_new_vertex_positions(percent_complete)
        update_opacity(percent_complete)
        viewer.repaint()

    def clear_location_cache(self):
        graph_layout = self.viewer.get_graph_layout()
        (graph_layout).clear()

    # Private Methods
    def initialize_vertex_locations(self):
        original_bounds = parent_vertex.bounds
        new_bounds = merged_vertex.bounds
        dy = (new_bounds.height - original_bounds.height) // 2

        parent_location = graph_layout.apply(parent_vertex)
        merged_location = Point2D.Double(parent_location.x, parent_location.y + dy)

        self.parent_start = parent_location
        self.parent_destination = parent_location
        child_start = graph_layout.apply(child_vertex)
        child_destination = parent_destination
        merged_destination = merged_location

        old_location_property = parent_vertex.location
        merged_vertex.set_location(old_location_property)
        graph_layout.set_location(merged_vertex, merged_destination)

        clear_location_cache()

    def update_new_vertex_positions(self, percent_complete):
        parent_destination_x = self.parent_destination.x
        delta_x = (parent_destination_x - self.parent_start.x) * percent_complete

        child_destination_y = self.child_destination.y
        delta_y = (child_destination_y - self.child_start.y) * percent_complete

        child_destination_x = self.child_destination.x
        delta_child_x = (child_destination_x - self.child_start.x) * percent_complete

        parent_destination_y = self.parent_destination.y
        delta_parent_y = (parent_destination_y - self.parent_start.y) * percent_complete

        new_parent_x = self.parent_start.x + delta_x
        new_parent_y = self.parent_start.y + delta_parent_y

        new_child_x = self.child_start.x + delta_child_x
        new_child_y = self.child_start.y + delta_y

        new_parent_location = Point2D.Double(new_parent_x, new_parent_y)
        new_child_location = Point2D.Double(new_child_x, new_child_y)

        parent_vertex.set_location(new_parent_location)
        child_vertex.set_location(new_child_location)

        clear_location_cache()
        graph_layout.set_location(parent_vertex, new_parent_location)
        graph_layout.set_location(child_vertex, new_child_location)

    def update_opacity(self, percent_complete):
        old_components_alpha = 1.0 - percent_complete
        parent_vertex.alpha = old_components_alpha
        child_vertex.alpha = old_components_alpha

        edges = get_edges(merged_vertex)
        for edge in edges:
            default_alpha = edge.default_alpha
            alpha = min(old_components_alpha, default_alpha)
            edge.set_alpha(alpha)

    def remove_old_vertex_and_edges(self):
        function_graph_data = self.controller.get_function_graph_data()
        graph = function_graph_data.function_graph
        graph.remove_vertex(parent_vertex)
        graph.remove_vertex(child_vertex)

class Point2D:
    def __init__(self, x=0.0, y=0.0):
        self.x = float(x)
        self.y = float(y)

class PropertySetter:
    @staticmethod
    def create_animator(duration, target, property_name, start_value, end_value):
        return None

    @staticmethod
    def set_acceleration(animator, acceleration):
        pass

    @staticmethod
    def set_deceleration(animator, deceleration):
        pass

class Caching:
    def clear(self):
        pass

def get_edges(vertex):
    graph = self.viewer.get_graph_layout().get_graph()
    edges = []
    
    in_edges = graph.in_edges(vertex)
    if in_edges is not None:
        for edge in in_edges:
            edges.append(edge)

    out_edges = graph.out_edges(vertex)
    if out_edges is not None:
        for edge in out_edges:
            edges.append(edge)

    return edges
```

Please note that Python does not have direct equivalent of Java's `Point2D` class. I used a simple custom class to represent 2D points. Also, some methods like `PropertySetter.create_animator`, `Caching.clear` and others are placeholders as they do not exist in the original code or their equivalents are different in Python.