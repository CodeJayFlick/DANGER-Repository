Here is the translation of the Java code into Python:

```Python
class VisualGraphAbstractGraphMousePlugin:
    def __init__(self):
        self.is_handling_mouse_events = False
        self.selected_vertex = None
        self.selected_edge = None

    def check_modifiers(self, e):
        return e.getModifiersEx() == self.modifiers

    def check_for_vertex(self, e):
        if not self.check_modifiers(e):
            self.selected_vertex = None
            return False

        viewer = self.get_viewer(e)
        pick_support = viewer.get_pick_support()
        layout = viewer.get_graph_layout()

        p = e.getPoint()
        selected_vertex = pick_support.get_vertex(layout.x, layout.y)

        if selected_vertex is None:
            return False

        e.consume()
        return True

    def check_for_edge(self, e):
        if not self.check_modifiers(e) or self.is_over_vertex(e):
            self.selected_edge = None
            return False

        viewer = self.get_viewer(e)
        pick_support = viewer.get_pick_support()
        layout = viewer.get_graph_layout()

        p = e.getPoint()
        selected_edge = pick_support.get_edge(layout.x, layout.y)

        if selected_edge is None:
            return False

        e.consume()
        self.is_handling_mouse_events = True
        return True

    def get_viewer(self, e):
        # This method should be implemented in the subclass.
        pass

    def install_cursor(self, new_cursor, e):
        viewer = self.get_viewer(e)
        viewer.set_cursor(new_cursor)

    def is_over_vertex(self, e):
        viewer = self.get_viewer(e)
        return GraphViewerUtils.get_vertex_from_point_in_view_space(viewer, e.getPoint()) is not None

    def is_over_edge(self, e):
        viewer = self.get_viewer(e)
        edge = GraphViewerUtils.get_edge_from_point_in_view_space(viewer, e.getPoint())

        if edge is None:
            return False

        return not self.is_over_vertex(e)

    def pick_vertex(self, vertex, viewer):
        picked_vertex_state = viewer.get_picked_vertex_state()

        if picked_vertex_state is None:
            return False

        if picked_vertex_state.is_picked(vertex) == False:
            picked_vertex_state.clear()
            picked_vertex_state.pick(vertex, True)
        return True

    def pick_edge(self, edge, viewer):
        picked_edge_state = viewer.get_picked_edge_state()

        if picked_edge_state is None:
            return False

        if picked_edge_state.is_picked(edge) == False:
            picked_edge_state.clear()
            picked_edge_state.pick(edge, True)
        return True

    def reset_state(self):
        self.is_handling_mouse_events = False
        self.selected_vertex = None
        self.selected_edge = None

    def should_show_cursor(self, e):
        return self.is_over_vertex(e)  # default to showing cursor over vertices

    def mouse_pressed(self, e):
        if not self.check_modifiers(e):
            return

        # override this method to do stuff
        pass

    def mouse_clicked(self, e):
        if not self.is_handling_mouse_events:
            return

        e.consume()
        self.reset_state()

    def mouse_dragged(self, e):
        if not self.is_handling_mouse_events:
            return

        e.consume()
        self.reset_state()

    def mouse_moved(self, e):
        if self.is_handling_mouse_events:
            e.consume()

        # only "turn on" the cursor; resetting is handled elsewhere (in the mouse driver)
        if self.should_show_cursor(e):
            self.install_cursor(cursor, e)

    def mouse_released(self, e):
        if self.is_handling_mouse_events:
            e.consume()

        if self.should_show_cursor(e):
            self.install_cursor(cursor, e)

    def mouse_entered(self, e):
        if self.should_show_cursor(e):
            self.install_cursor(cursor, e)
            e.consume()

    def mouse_exited(self, e):
        self.install_cursor(Cursor.get_predefined_cursor(Cursor.DEFAULT_CURSOR), e)
```

Please note that the `get_viewer`, `install_cursor` and other methods are placeholders for actual implementation in a subclass.