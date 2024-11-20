Here is the translation of the Java code into Python:

```Python
import math

class SplitVertexFunctionGraphJob:
    def __init__(self, controller, viewer, to_split_vertex, new_parent_vertex, new_child_vertex, use_animation):
        self.controller = controller
        self.viewer = viewer
        self.to_split_vertex = to_split_vertex
        self.parent_vertex = new_parent_vertex
        self.child_vertex = new_child_vertex
        self.use_animation = use_animation

    def can_shortcut(self):
        return False

    def shortcut(self):
        raise UnsupportedOperationException("Cannot cancel this job: " + str(self))

    def create_animator(self):
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
        graph_layout.set_location(parent_vertex, parent_destination)
        graph_layout.set_location(child_vertex, child_destination)
        remove_old_vertex_and_edges()

        update_opacity(1.0)
        controller.synchronize_program_location_after_edit()
        restore_edge_display_attributes()
        viewer.repaint()

    def set_percent_complete(self, percent_complete):
        trace("setPercentComplete() callback: " + str(percent_complete))
        update_new_vertex_positions(percent_complete)
        update_opacity(percent_complete)
        viewer.repaint()

    def clear_location_cache(self):
        layout = graph_layout
        ((Caching) layout).clear()

    # Private Methods

    def initialize_vertex_locations(self):
        old_location = graph_layout.apply(to_split_vertex)
        parent_location = (Point2D(old_location.x, old_location.y))
        
        original_bounds = to_split_vertex.bounds()
        new_bounds = parent_vertex.bounds()
        dy = (new_bounds.height - original_bounds.height) // 2
        parent_location.set_x(parent_location.get_x() + dy)

        self.parent_start = parent_location
        self.parent_destination = parent_location
        child_start = parent_location

        to_split_vertex.location = old_location
        graph_layout.set_location(to_split_vertex, old_location)
        
        child_start_location = (Point2D(child_start.x, child_start.y))
        child_vertex.location = old_location
        graph_layout.set_location(child_vertex, child_start_location)

        self.child_destination = Point2D(child_start_location.get_x(), parent_bounds.height + GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING)
        
        clear_location_cache()

    def update_opacity(self, percent_complete):
        alpha = 1.0 - percent_complete
        to_split_vertex.alpha = alpha

        edges = get_edges(to_split_vertex)
        for edge in edges:
            default_alpha = edge.default_alpha()
            if default_alpha > alpha:
                edge.set_alpha(alpha)

        new_components_alpha = percent_complete
        parent_vertex.alpha = new_components_alpha
        child_vertex.alpha = new_components_alpha
        
        edges = get_edges(parent_vertex)
        for edge in edges:
            default_alpha = edge.default_alpha()
            if default_alpha > new_components_alpha:
                edge.set_alpha(new_components_alpha)

        edges = get_edges(child_vertex)
        for edge in edges:
            default_alpha = edge.default_alpha()
            if default_alpha > new_components_alpha:
                edge.set_alpha(new_components_alpha)

    def update_new_vertex_positions(self, percent_complete):
        parent_destination_x = self.parent_destination.x
        delta_x = (parent_destination_x - self.parent_start.x) * percent_complete

        child_destination_y = self.child_destination.y
        delta_y = (child_destination_y - self.child_start.y) * percent_complete
        
        new_parent_x = self.parent_start.get_x() + delta_x
        new_parent_y = self.parent_start.get_y() + delta_y

        new_child_x = self.child_start.get_x() + delta_x
        new_child_y = self.child_start.get_y() + delta_y

        parent_location = Point2D(new_parent_x, new_parent_y)
        child_location = Point2D(new_child_x, new_child_y)

        to_split_vertex.location = parent_location
        graph_layout.set_location(to_split_vertex, parent_location)

        child_vertex.location = child_location
        graph_layout.set_location(child_vertex, child_location)

    def get_edges(self, vertex):
        graph = self.graph_layout.get_graph()
        edges = []
        
        in_edges = graph.in_edges(vertex)
        if in_edges:
            for edge in in_edges:
                edges.append(edge)

        out_edges = graph.out_edges(vertex)
        if out_edges:
            for edge in out_edges:
                edges.append(edge)

        return edges

    def remove_old_vertex_and_edges(self):
        function_graph_data = self.controller.get_function_graph_data()
        graph = function_graph_data.function_graph
        graph.remove_vertex(to_split_vertex)

# Other methods and classes are not translated as they were missing from the provided Java code.