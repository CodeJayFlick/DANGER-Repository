class MultipleLabelsRenderer:
    class RendererType(enum.Enum):
        SOURCE = "source"
        DESTINATION = "destination"

    MULTIPLE_LABELS_ICON = ResourceManager.load_image("images/application_view_detail.png")
    SINGLE_NAME_TOOLTIP = "Doesn't have multiple labels."
    # MULTI_NAME_TOOLTIP = f"Has multiple labels. The number indicates how many. Labels can be viewed using the dual listing of Markup Items."

    def __init__(self, type):
        self.type = type

    @staticmethod
    def configure_renderer_for_multiple_labels_indicator(table, row, renderer, symbols):
        renderer.text = ""
        renderer.horizontal_alignment = CENTER
        label_count = len(symbols)
        if label_count > 1:
            renderer.icon = MultipleLabelsRenderer.MULTIPLE_LABELS_ICON
            renderer.text = f"{label_count}"
            
            # Set up the tooltip information.
            display_string = self.type.value
            buffer = StringBuffer()
            buffer.append(f"Has {label_count} {display_string} labels. Labels can also be viewed using the dual listing of Markup Items.")
            buffer.append("\n")
            for i, symbol in enumerate(symbols):
                if i == 20:
                    # Only show first 20 names.
                    buffer.append("\n...")
                    break
                buffer.append(f"\n{symbol.name}")
            text = buffer.toString()
            renderer.tooltip_text = HTMLUtilities.to_wrapped_html(text)
        else:
            renderer.icon = None
            renderer.text = ""
            renderer.tooltip_text = MultipleLabelsRenderer.SINGLE_NAME_TOOLTIP

    def get_table_cell_renderer_component(self, data):
        renderer = super().get_table_cell_renderer_component(data)

        value = data.value
        table = data.table
        row_view_index = data.row_view_index

        if not isinstance(value, list) or len(value) != 2:
            raise AssertionError("Incorrect column value for the match's multiple labels indicator column")

        self.configure_renderer_for_multiple_labels_indicator(table, row_view_index, renderer, value)

        return renderer

    def get_filter_string(self, t, settings):
        return str(len(t))
