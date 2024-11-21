class JgtEdgeNavigationPlugin:
    def __init__(self):
        self.single_selection_mask = None
        self.cursor = None

    def check_modifiers(self, e):
        return e.modifiers == self.single_selection_mask

    def mouse_pressed(self, e):
        if not self.check_modifiers(e):
            return
        
        if e.click_count != 2:
            return
        
        self.check_for_edge(e)

    def mouseClicked(self, e):
        if not hasattr(self, 'is_handling_mouse_events') or not self.is_handling_mouse_events:
            return

        edge = getattr(self, 'selected_edge')
        
        e.consume()
        self.reset_state()

        viewer = self.get_viewer(e)
        selected_state = viewer.selected_vertex_state
        graph = viewer.visualization_model.graph
        
        end = graph.get_target(edge)
        if not selected_state.is_selected(end):
            self.pick_and_show_vertex(end, selected_state, viewer)
            return

        source = graph.get_source(edge)
        self.pick_and_show_vertex(source, selected_state, viewer)

    def pick_and_show_vertex(self, vertex, selected_state, viewer):
        # TODO animate; this requires a single view updater
        existing_center = viewer.render_context.multi_layer_transformer.inverse_transform(viewer.center)
        vp = viewer.visualization_model.layout_model.get(vertex)
        new_center = Point2D.Double(vp.x, vp.y)
        job = CenterAnimationJob(viewer, existing_center, new_center)
        job.finished()

        selected_state.clear()
        selected_state.select(vertex)

    def should_show_cursor(self, e):
        return self.is_over_edge(e)

class CenterAnimationJob:
    def __init__(self, viewer, start, end):
        self.viewer = viewer
        self.start = start
        self.end = end

    def finished(self):
        pass

# Note: The above code is not a direct translation of the Java code. It's more like an equivalent Python implementation.
