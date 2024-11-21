Here is the equivalent Python code:

```Python
class DebuggerBreakpointEnablementTableCellRenderer:
    def __init__(self):
        self.setHorizontalAlignment("CENTER")

    @staticmethod
    def icon_for_enablement(en):
        if en == "NONE":
            return None
        elif en == "ENABLED":
            return "ICON_BREAKPOINT_ENABLED_MARKER"
        elif en == "DISABLED":
            return "ICON_BREAKPOINT_DISABLED_MARKER"
        elif en == "INEFFECTIVE ENABLED":
            return "ICON_BREAKPOINT_INEFFECTIVE_E_MARKER"
        elif en == "INEFFECTIVE DISABLED":
            return "ICON_BREAKPOINT_INEFFECTIVE_D_MARKER"
        elif en == "ENABLED DISABLED":
            return "ICON_BREAKPOINT_MIXED_ED_MARKER"
        elif en == "DISABLED ENABLED":
            return "ICON_BREAKPOINT_MIXED_DE_MARKER"
        else:
            raise AssertionError(en)

    def get_table_cell_renderer_component(self, data):
        super().get_table_cell_renderer_component(data)
        en = data.get_value()
        self.set_icon(self.icon_for_enablement(en))
        self.setHorizontalAlignment("CENTER")
        self.set_text("")
        self.setToolTipText(str(en))
        return self

    @staticmethod
    def get_filter_string(t, settings):
        return str(t)

# Example usage:
renderer = DebuggerBreakpointEnablementTableCellRenderer()
data = {"value": "ENABLED"}
component = renderer.get_table_cell_renderer_component(data)
```

Please note that Python does not have direct equivalent of Java's Swing and AWT libraries. The above code is a simple translation of the given Java code to Python, but it may not work exactly as expected in a real-world application without proper GUI library like Tkinter or PyQt.