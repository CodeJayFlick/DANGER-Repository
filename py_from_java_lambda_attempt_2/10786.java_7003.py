Here is the translation of the Java code into Python:

```Python
class JungPickingGraphMousePlugin:
    def __init__(self):
        self.vertex = None
        self.edge = None
        self.offsetx = 0
        self.offsety = 0
        self.locked = False
        self.addToSelectionModifiers = InputEvent.BUTTON1_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK

    @property
    def lens_color(self):
        return self._lens_color

    @lens_color.setter
    def lens_color(self, value):
        self._lens_color = value

    class LensPaintable:
        def paint(self, graphics_context):
            old_color = graphics_context.get_source().get_font().get_foreground()
            graphics_context.set_source_rgb(*self.lens_color)
            ((graphics.Context2D) graphics_context).draw_rectangle(0, 0, self.rect.width, self.rect.height)
            graphics_context.set_source_rgb(*old_color)

        def use_transform(self):
            return False

    @property
    def locked(self):
        return self._locked

    @locked.setter
    def locked(self, value):
        self._locked = value

    def mouse_pressed(self, event):
        down = event.get_position()
        visualization_viewer = VisualizationViewer(event.getSource())
        graph_element_accessor = visualization_viewer.get_pick_support()
        picked_vertex_state = visualization_viewer.get_picked_vertex_state()

        if graph_element_accessor is not None and picked_vertex_state is not None:
            layout = visualization_viewer.get_graph_layout()
            modifiers = event.get_modifiers_ex()

            if modifiers == self.modifiers:
                rect.set_frame_from_diagonal(down, down)
                vertex = graph_element_accessor.get_vertex(layout, *down)

                if vertex is not None:
                    picked_vertex_state.clear()
                    picked_vertex_state.pick(vertex, True)

                    q = layout.apply(vertex)
                    gp = visualization_viewer.get_render_context().get_multi_layer_transformer().inverse_transform(0, 1)  # Layer.LAYOUT
                    offsetx = (gp[0] - q[0])
                    offsety = (gp[1] - q[1])

                else:
                    visualization_viewer.add_post_render_paintable(self.lens_paintable)
                    picked_edge_state = visualization_viewer.get_picked_edge_state()
                    picked_vertex_state.clear()

            elif modifiers == self.addToSelectionModifiers:
                rect.set_frame_from_diagonal(down, down)

        if vertex is not None:
            event.consume()

    def mouse_released(self, event):
        visualization_viewer = VisualizationViewer(event.getSource())

        if event.get_modifiers_ex() == self addToSelectionModifiers:
            if down is not None:
                out = event.get_position()
                if hey_thats_too_close(down, out, 5) is False:
                    pick_contained_vertices(visualization_viewer, down, out, False)

        else:  # Mouse released without the 'add to selection' modifiers. See if we have been dragging
            if down is not None:
                out = event.get_position()
                if hey_thats_too_close(down, out, 5) is False:
                    pick_contained_vertices(visualization_viewer, down, out, True)

        self.down = None
        self.vertex = None
        self.edge = None
        rect.set_frame(0, 0, 0, 0)
        visualization_viewer.remove_post_render_paintable(self.lens_paintable)
        visualization_viewer.repaint()

    def mouse_dragged(self, event):
        if not self.locked:
            visualization_viewer = VisualizationViewer(event.getSource())

            if self.vertex is not None:
                p = event.get_position()
                graph_point = visualization_viewer.get_render_context().get_multi_layer_transformer().inverse_transform(0, 1)  # Layer.LAYOUT
                dx = (graph_point[0] - down[0])
                dy = (graph_point[1] - down[1])

                for v in picked_vertex_state.picked:
                    vp = layout.apply(v)
                    vp.set_location(vp[0] + dx, vp[1] + dy)
                    layout.set_location(v, vp)

                self.down = p

            else:  # If the mouse is not over a Vertex, draw the rectangle to select multiple Vertices
                out = event.get_position()
                if (event.get_modifiers_ex() == self.modifiers or event.get_modifiers_ex() == self.addToSelectionModifiers):
                    rect.set_frame_from_diagonal(down, out)

            if self.vertex is not None:
                event.consume()

    def hey_thats_too_close(self, p1, p2, min_distance):
        return abs(p1[0] - p2[0]) < min_distance and abs(p1[1] - p2[1]) < min_distance

    def pick_contained_vertices(self, visualization_viewer, down, out, clear):
        layout = visualization_viewer.get_graph_layout()
        picked_vertex_state = visualization_viewer.get_picked_vertex_state()

        if picked_vertex_state is not None:
            if clear:
                picked_vertex_state.clear()

            graph_element_accessor = visualization_viewer.get_pick_support()
            vertices = graph_element_accessor.get_vertices(layout, rect)

            for v in vertices:
                picked_vertex_state.pick(v, True)
```

Note that I've made some assumptions about the Python code structure and naming conventions.