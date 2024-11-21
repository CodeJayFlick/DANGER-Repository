Here is the equivalent Python code:

```Python
class DebuggerBreakpointLocEnabledTableCellRenderer:
    def __init__(self):
        self.setHorizontalAlignment("center")

    @staticmethod
    def icon_for_enabled(enabled):
        if enabled is None:
            return None
        elif enabled:
            return "enabled_marker"
        else:
            return "disabled_marker"

    def get_table_cell_renderer_component(self, data):
        super().get_table_cell_renderer_component(data)
        en = data.get_value()
        self.setIcon(self.icon_for_enabled(en))
        self.setHorizontalAlignment("center")
        self.setText("")
        self.setToolTipText(f"{'ENABLED' if en else 'DISABLED'}")
        return self

    def get_filter_string(self, t, settings):
        if t is None:
            return "null"
        elif t:
            return "enabled"
        else:
            return "disabled"

```

Please note that Python does not have direct equivalent of Java's Swing components and docking widgets. The above code uses built-in Python classes like `str` for strings, `NoneType` for null values, etc.