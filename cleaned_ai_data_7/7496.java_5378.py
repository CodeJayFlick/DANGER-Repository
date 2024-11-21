class EmptyLayout:
    NAME = "Empty Layout"

    def __init__(self, graph):
        pass  # stub for now

    def initialize(self):
        pass  # stub for now

    def reset(self):
        pass  # stub for now

    def get_edge_renderer(self):
        return ArticulatedEdgeRenderer()

    def get_edge_shape_transformer(self):
        return ArticulatedEdgeTransformer()

    def perform_initial_grid_layout(self, g):
        return None  # Note: this is not called, since we overrode calculate_locations()

    def calculate_locations(self, g, task_monitor):
        return LayoutPositions.create_empty_positions()

    def create_cloned_layout(self, new_graph):
        return EmptyLayout(FunctionGraph(new_graph))

    def clone_layout(self, new_graph):
        return super().clone_layout(new_graph)

    def uses_edge_articulations(self):
        return False

    def set_location(self, v, location, change_type):
        pass  # stub for now

    def add_layout_listener(self, listener):
        pass  # stub for now

    def remove_layout_listener(self, listener):
        pass  # stub for now

    def dispose(self):
        pass  # stub for now

    @property
    def visual_graph(self):
        return self.graph


class ArticulatedEdgeRenderer:
    pass  # implementation not provided in the given Java code


class ArticulatedEdgeTransformer:
    pass  # implementation not provided in the given Java code


class LayoutPositions:
    @staticmethod
    def create_empty_positions():
        pass  # implementation not provided in the given Java code

