Here is the translation of the Java code into Python:

```Python
class DataTypeCellRenderer:
    def __init__(self, original_data_type_manager):
        self.original_dtm = original_data_type_manager

    def get_table_cell_renderer_component(self, data):
        value = data.get_value()

        dt_string = ""
        tooltip_text = None
        use_red = False
        dt = None

        if isinstance(value, DataTypeInstance):
            dt = (value).get_data_type()
            tooltip_text = self.get_data_type_tooltip(dt)
            dt_string = dt.get_display_name()
            if not dt.is_yet_defined():
                use_red = True

        render_data = data.copy_with_new_value(dt_string)

        c = super().get_table_cell_renderer_component(render_data)

        c.set_tool_tip_text(tooltip_text)

        if use_red:
            c.set_foreground_color(Color.RED)

        return c

    def get_data_type_tooltip(self, dt):
        dtype_manager = dt.get_data_type_manager()
        source_archive = dt.get_source_archive()

        local_source = (source_archive is None) or \
                       ((dtype_manager is not None) and
                        self.original_dtm.is_equal(dtype_manager.get_universal_id(),
                                                    source_archive.get_source_archive_id()))

        if local_source:
            source_archive = self.original_dtm.get_source_archive(self.original_dtm.get_universal_id())

        found_dt = self.original_dtm.get_data_type(dt.get_data_type_path())

        display_name = ""

        if (found_dt is not None) and (dtype_manager is not None):
            display_name = dtype_manager.get_name()
        display_name += dt.get_path_name()

        if not local_source:
            display_name += " (" + source_archive.get_name() + ")"

        display_name = HTMLUtilities.friendly_encode_html(display_name)

        tool_tip_text = ToolTipUtils.get_tool_tip_text(dt)
        header_text = "<HTML><b>" + display_name + "</b><BR>"
        tool_tip_text = tool_tip_text.replace("<HTML>", header_text)

        return tool_tip_text
```

Please note that this translation is not perfect, as Python and Java have different syntaxes. This code may need to be adjusted based on the specific requirements of your project.