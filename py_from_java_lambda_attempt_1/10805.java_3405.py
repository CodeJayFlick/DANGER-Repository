Here is a translation of the Java code into equivalent Python:

```Python
class VisualGraphScalingGraphMousePlugin:
    def __init__(self):
        # no modifiers set here--we will always check ourselves
        self.scaling_control = VisualGraphScalingControl()
        super().__init__(self.scaling_control, 0, 1 / 1.1f, 1.1f)
        self.zoom_at_mouse = True

    def check_modifiers(self, e):
        return self.is_zoom_modifier(e)

    # see also FunctionGraphScrollWheelPanningPlugin
    def is_zoom_modifier(self, e):

        viewer = self.get_graph_viewer(e)
        if viewer is None:
            return False

        options = viewer.options()
        scroll_wheel_pans = options.scroll_wheel_pans
        scroll_wheel_modifier_toggle = DockingUtils.CONTROL_KEY_MODIFIER_MASK
        event_modifiers = e.modifiers_ex
        if scroll_wheel_pans:
            # scrolling will zoom if modified (unmodified in this case means to pan)
            return (scroll_wheel_modifier_toggle & event_modifiers) == scroll_wheel_modifier_toggle

        # scrolling *will* zoom only when not modified (modified in this case means to pan)
        return not ((scroll_wheel_modifier_toggle & event_modifiers) == scroll_wheel_modifier_toggle)

    def get_graph_viewer(self, e):
        pass  # This method is missing the implementation from Java.

class VisualGraphScalingControl:
    pass  # This class is missing its definition and methods in Python.

class DockingUtils:
    CONTROL_KEY_MODIFIER_MASK = None  # This constant needs to be defined.
```

Please note that this translation does not include all classes (`VisualGraphScalingControl`, `DockingUtils`) as they are not provided.