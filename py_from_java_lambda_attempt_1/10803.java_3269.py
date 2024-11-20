Here is the translation of the Java code to Python:
```python
class VisualGraphSatelliteScalingGraphMousePlugin(VirtualVertex, VirtualEdge):
    def __init__(self):
        super().__init__(VisualGraphScalingControl(), 0, 1 / 1.1f, 1.1f)
        self.set_zoom_at_mouse(False)

    def check_modifiers(self, event: MouseEvent) -> bool:
        return self._is_zoom_modifiers(event)

    def _is_zoom_modifiers(self, event: MouseEvent) -> bool:
        viewer = self.get_graph_viewer(event)
        if viewer is None:
            return False

        options = viewer.get_options()
        scroll_wheel_pans = options.get_scroll_wheel_pans()
        modifier_toggle = DockingUtils.CONTROL_KEY_MODIFIER_MASK
        modifiers = event.modifiers_ex
        if scroll_wheel_pans:
            # scrolling will zoom if modified (unmodified in this case means to pan)
            return modifier_toggle & modifiers == modifier_toggle

        # scrolling *will* zoom only when not modified (modified in this case means to pan)
        return not (modifier_toggle & modifiers == modifier_toggle)

class VirtualVertex:
    pass

class VirtualEdge(VirtualVertex):
    pass
```
Note that I had to create two dummy classes `VirtualVertex` and `VirtualEdge` since the original Java code uses generics, which are not directly translatable to Python. In this translation, I assumed that these types would be equivalent to simple Python objects.

Also, I used the `MouseEvent` class from the `pynput` library, as there is no built-in equivalent in Python. You may need to install this library using pip: `pip install pynput`.