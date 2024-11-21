class VertexMouseInfo:
    def __init__(self, original_mouse_event, vertex, vertex_based_click_point, viewer):
        self.original_mouse_event = original_mouse_event
        self.vertex = vertex
        self.viewer = viewer
        
        component = vertex.get_component()
        deepest_component = SwingUtilities.get_deepest_component_at(component, int(vertex_based_click_point[0]), int(vertex_based_click_point[1]))
        self.set_clicked_component(deepest_component, vertex_based_click_point)

    def is_scaled_past_interaction_threshold(self):
        render_context = viewer.get_render_context()
        multi_layer_transformer = render_context.get_multi_layer_transformer()
        view_transformer = multi_layer_transformer.get_transformer('VIEW')
        scale = view_transformer.get_scale()
        return scale < GraphViewerUtils.INTERACTION_ZOOM_THRESHOLD

    def get_cursor_for_clicked_component(self):
        if self.is_grab_area():
            return Cursor.HAND_CURSOR
        elif not self.is_vertex_selected():
            return Cursor.HAND_CURSOR
        else:
            return Cursor.DEFAULT_CURSOR

    def is_grab_area(self):
        if self.is_button_click():
            return False
        return vertex.is_grabbable(self.get_clicked_component())

    def is_button_click(self):
        clicked_component = self.get_clicked_component()
        if isinstance(clicked_component, JButton):
            return True
        else:
            return False

    def is_vertex_selected(self):
        picked_vertex_state = viewer.get_picked_vertex_state()
        return picked_vertex_state.is_picked(vertex)

    def select_vertex(self, add_to_selection):
        # when the user manually clicks a vertex, we no longer want an edge selected
        picked_edge_state = viewer.get_picked_edge_state()
        picked_edge_state.clear()
        if self.is_vertex_selected():
            return

        picked_state = viewer.get_gpicked_vertex_state()
        picked_state.pick_to_sync(vertex, add_to_selection)

    def get_vertex_component(self):
        return vertex.get_component()

    def get_clicked_component(self):
        return self.moused_destination_component

    def get_viewer(self):
        return self.viewer

    def get_vertex(self):
        return self.vertex

    def get_deepest_component_based_click_point(self):
        return self.original_mouse_event.point

    @staticmethod
    def set_clicked_component(clicked_component, vertex_based_point):
        VertexMouseInfo.moused_destination_component = clicked_component
        
        component_point = (int(vertex_based_point[0]), int(vertex_based_point[1]))

        # default values...
        new_event_source = vertex.get_component()
        point_in_clicked_component_coordinates = component_point
        if clicked_component is not None:
            # the component can be null when it hasn't been shown yet, like in fast rendering
            new_event_source = clicked_component
            point_in_clicked_component_coordinates = SwingUtilities.convert_point(vertex.get_component(), component_point, clicked_component)
        
        translated_mouse_event = VertexMouseInfo.create_mouse_event_from_source(new_event_source, original_mouse_event, point_in_clicked_component_coordinates)

    @staticmethod
    def get_event_source():
        return original_mouse_event.source

    @staticmethod
    def get_original_mouse_event():
        return original_mouse_event

    @staticmethod
    def get_translated_mouse_event():
        return translated_mouse_event

    def forward_event(self):
        if self.moused_destination_component is None:
            return
        
        self.moused_destination_component.dispatch_event(translated_mouse_event)
        if not self.is_popup_click():
            # don't consume popup because we want DockableComponent to get the event also to popup
            original_mouse_event.consume()

    def simulate_mouse_entered_event(self):
        if self.moused_destination_component is None:
            return
        
        mouse_entered_event = VertexMouseInfo.create_mouse_entered_event()
        self.moused_destination_component.dispatch_event(mouse_entered_event)
        viewer.repaint()

    def simulate_mouse_exited_event(self):
        if self.moused_destination_component is None:
            return
        
        mouse_exited_event = VertexMouseInfo.create_mouse_exited_event()
        self.moused_destination_component.dispatch_event(mouse_exited_event)
        viewer.repaint()

    @staticmethod
    def create_mouse_entered_event():
        return MouseEvent(self.moused_destination_component, MOUSE_ENTERED, System.currentTimeMillis(), 0, 0, 0, False)

    @staticmethod
    def create_mouse_exited_event():
        return MouseEvent(self.moused_destination_component, MOUSE_EXITED, System.currentTimeMillis(), 0, 0, 0, False)

    @staticmethod
    def create_mouse_event_from_source(source, progenitor, click_point):
        return MouseEvent(source, progenitor.id, progenitor.when, progenitor.modifiers | progenitor.modifiers_ex, int(click_point[0]), int(click_point[1]), progenitor.click_count, progenitor.is_popup_trigger, progenitor.button)

    def is_popup_click(self):
        return self.original_mouse_event.get_button() == MOUSE_BUTTON3

    def __str__(self):
        return f"{{\n\tvertex: {self.vertex},\n\tclickedComponent: {self.moused_destination_component},\n\tevent: {self.original_mouse_event},\n\ttranslatedEvent: {self.translated_mouse_event}\n}}"
