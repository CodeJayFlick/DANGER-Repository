Here is the translation of the given Java code into equivalent Python:

```Python
class VisualGraphScrollWheelPanningPlugin:
    def __init__(self):
        pass

    def check_modifiers(self, e):
        return e.modifiers == self.modifiers

    def mouse_wheel_moved(self, e):
        if not self.is_scroll_modifiers(e):
            return

        self.pan(e)

    def pan(self, e):
        viewer = self.get_graph_viewer(e)
        scroll_amount = 1
        if e.scroll_type == MouseWheelEvent.WHEEL_UNIT_SCROLL:
            scroll_amount = e.scroll_amount
        wheel_rotation = -e.wheel_rotation
        arbitrary_acceleration = 10

        scale = GraphViewerUtils.get_graph_scale(viewer)

        unscaled_offset = wheel_rotation * scroll_amount * arbitrary_acceleration
        offset = int((unscaled_offset / scale))

        new_point = (0, offset)
        if e.alt_down:
            new_point = (offset, 0)

        updater = viewer.view_updater()
        updater.move_viewer_location_without_animation(new_point)

    def is_scroll_modifiers(self, e):
        viewer = self.get_graph_viewer(e)
        options = viewer.options
        scroll_wheel_pans = options.scroll_wheel_pans

        if not scroll_wheel_pans:
            return True

        event_modifiers = e.modifiers
        control_key_modifier_mask = 0x0002

        if (control_key_modifier_mask & event_modifiers) == control_key_modifier_mask:
            return False

        return True

    def get_graph_viewer(self, e):
        # implement this method to retrieve the graph viewer from the mouse wheel event
        pass


class MouseWheelEvent:
    WHEEL_UNIT_SCROLL = 0x0001
    WHEEL_UNIT_SCROLL = 0x0002

    def __init__(self):
        self.modifiers = 0
        self.scroll_type = 0
        self.wheel_rotation = 0
        self.alt_down = False


class GraphViewer:
    def __init__(self, options):
        self.options = options
        self.view_updater()

    def view_updater(self):
        # implement this method to retrieve the graph viewer's update object
        pass

    def get_options(self):
        return self.options

    def move_viewer_location_without_animation(self, new_point):
        # implement this method to move the graph viewer location without animation
        pass


class GraphViewerUtils:
    @staticmethod
    def get_graph_scale(viewer):
        # implement this method to retrieve the scale of the current graph from the given view
        pass

```

Please note that Python does not have direct equivalent for Java's MouseWheelEvent, so I created a simple class `MouseWheelEvent` with some basic properties. Also, there are several methods in your original code which seem to be related to GUI and event handling (like getting graph viewer from mouse wheel event), these were left as is because they require specific implementation based on the actual Python framework or library you're using for creating a graphical interface.