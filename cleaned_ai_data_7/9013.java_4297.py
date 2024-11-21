class MatchTableRenderer:
    LOCKED_OUT_BACKGROUND_COLOR = (239, 239, 239)

    def get_table_cell_renderer_component(self, data):
        renderer_component = super().get_table_cell_renderer_component(data)
        
        table = data.get_table()
        row_object = data.get_row_object()
        is_selected = data.is_selected()

        match = row_object
        if match is None:
            return renderer_component

        association = match.get_association()
        if not is_selected and association is not None:
            default_background_color = renderer_component.get_background()
            background_color = self.get_background_color(association, table, default_background_color)
            renderer_component.set_background(background_color)

        return renderer_component

    def get_background_color(self, association, table, default_background_color):
        status = association.get_status()
        if status == 'BLOCKED':
            return tuple([self.LOCKED_OUT_BACKGROUND_COLOR[i] for i in range(3)])
        else:
            return tuple(default_background_color)
