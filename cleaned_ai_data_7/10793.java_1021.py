class VisualGraphEventForwardingGraphMousePlugin:
    def __init__(self):
        self.mouse_pressed_info = None
        self.current_mouse_entered_info = None
        self.is_handling_event = False

    def check_modifiers(self, e):
        event_modifiers = e.getModifiersEx()
        return (event_modifiers & self.get_modifiers()) == event_modifiers

    def turn_off_control_key(self, event_modifiers):
        return event_modifiers & (~DockingUtils.CONTROL_KEY_MODIFIER_MASK)

    def is_control_click(self, e):
        all_modifiers = e.getModifiersEx()
        os_specific_mask = DockingUtils.CONTROL_KEY_MODIFIER_MASK
        return (all_modifiers & os_specific_mask) == os_specific_mask

    def mouse_pressed(self, e):
        self.mouse_pressed_info = None
        self.is_handling_event = False

        if not self.check_modifiers(e):
            return

        vertex_mouse_info = self.get_translated_mouse_info(e)
        if vertex_mouse_info is None:
            return

        if vertex_mouse_info.is_scaled_past_interaction_threshold():
            return

        self.update_cursor(vertex_mouse_info)

        if self.allow_header_click_through_to_lower_level_mouse_handlers(vertex_mouse_info):
            return

        self.is_handling_event = True
        self.mouse_pressed_info = vertex_mouse_info

    def get_translated_mouse_info(self, e):
        viewer = self.get_graph_viewer(e)
        return GraphViewerUtils.convert_mouse_event_to_vertex_mouse_event(viewer, e)

    def allow_header_click_through_to_lower_level_mouse_handlers(self, info):
        if info.is_popup_click():
            return False
        return info.is_grab_area()

    # ... and so on for the rest of the methods

