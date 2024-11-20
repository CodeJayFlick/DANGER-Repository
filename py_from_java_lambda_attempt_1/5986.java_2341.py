Here is the translation of the Java code into Python:

```Python
class PreviewDataTableCellRenderer:
    DEFAULT_OFFCUT_FOREGROUND_COLOR = (255, 0, 0)
    DEFAULT_SELECTED_OFFCUT_FOREGROUND_COLOR = (255, 102, 153)

    def get_table_cell_renderer_component(self, data):
        renderer = super().get_table_cell_renderer_component(data)  # Assuming a parent class with this method
        value = data.get_value()
        table = data.get_table()
        is_selected = data.is_selected()

        if value is None:
            return renderer

        if not isinstance(value, PreviewTableCellData):  # Assuming a separate class for PreviewTableCellData
            print("Renderer is not being used on " + str(PreviewTableCellData))
            return renderer

        preview_data = value
        preview = preview_data.get_display_string()
        is_offcut = preview_data.is_offcut()
        tooltip_text = preview_data.get_html_display_string()

        foreground_color = self.get_foreground(table, is_selected, is_offcut)

        renderer.set_text(preview)
        renderer.set_font(self.get_fixed_width_font())
        renderer.set_foreground(foreground_color)
        renderer.set_tooltip_text(tooltip_text)

        return renderer

    def get_foreground(self, table, is_selected, is_offcut):
        if not is_offcut:
            return self.get_foreground()

        focused = table.has_focus()
        if not focused:
            return (255, 0, 0)  # darker
        else:
            return is_selected and (153, 51, 204) or (102, 51, 102)

    def get_filter_string(self, t, settings):
        return str(t.get_display_string())
```

Please note that Python does not have direct equivalent of Java's Swing components. The code above assumes the existence of a parent class with `get_table_cell_renderer_component` method and uses print statement for error message instead of Msg.error as in the original Java code.