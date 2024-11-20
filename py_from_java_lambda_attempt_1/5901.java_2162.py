Here is a translation of the Java code into equivalent Python:

```Python
class CodeUnitTableCellRenderer:
    def get_table_cell_renderer_component(self, data):
        component = super().get_table_cell_renderer_component(data)
        
        value = data.get_value()
        
        if value is None:
            return component
        
        # this class only handles CodeUnitTableCellData objects
        if not isinstance(value, CodeUnitTableCellData):
            Msg.error(self, f"Renderer is not being used on {CodeUnitTableCellData.__name__}")
            return component
        
        cu_data = value
        display_strings = cu_data.get_display_strings()
        tooltip_text = cu_data.get_html_display_string()

        if len(display_strings) > 1:
            component = self.get_multi_line_renderer(display_strings)
        else:
            component = self.get_single_line_renderer(display_strings[0] if display_strings else "")

        component.set_tooltip_text(tooltip_text)

        return component

    def get_single_line_renderer(self, display_text):
        self.set_text(display_text)
        self.set_font(self.get_fixed_width_font())
        return self

    def get_multi_line_renderer(self, display_strings):
        panel = JPanel(GridLayout(len(display_strings), 1))
        panel.set_opaque(True)
        panel.set_background(self.get_background())
        panel.set_border(self.get_border())

        for string in display_strings:
            label = GDLabel()
            
            # configure the renderer for display
            label.set_background(self.get_background())
            label.set_horizontal_alignment(self.get_horizontal_alignment())
            label.set_opacity(is_opaque())
            label.set_border(get_no_focus_border())
            label.set_font(self.get_fixed_width_font())
            label.set_text(string)
            panel.add(label)

        return panel

    def get_filter_string(self, t, settings):
        if t is None:
            return ""

        return t.get_display_string()
```

Please note that this translation assumes the following:

- The `Msg` class and its methods are equivalent to Java's logging mechanism.
- The `JPanel`, `GridLayout`, `JLabel`, and other GUI components have been replaced with Python equivalents (e.g., Tkinter or PyQt).
- The `CodeUnitTableCellData` class has a similar structure in both languages, with the same attributes (`display_strings`, `html_display_string`) and methods.
- Some Java-specific features like exception handling are not included here.