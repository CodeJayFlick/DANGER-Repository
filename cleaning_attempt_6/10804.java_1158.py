class VisualGraphSatelliteTranslatingGraphMousePlugin(V):
    def __init__(self):
        super().__init__()
        self.cursor = Cursor.get_predefined_cursor(Cursor.MOVE_CURSOR)
        self.did_drag = False
        self.down = None

    def should_show_cursor(self, e):
        return self.is_in_satellite_lens_area(e)

    def mouse_dragged(self, e):
        if not self.check_modifiers(e) or not self.is_handling_mouse_events:
            return
        self.did_drag = True
        e.consume()
        satellite_viewer = e.get_source()
        view_master = (satellite_viewer).get_master()
        model_transformer_master = view_master.get_render_context().get_multi_layer_transformer().get_transformer(Layer.LAYOUT)
        transformed_point = self.get_delta_for_view_space_points_in_layout_space(e.get_point(), None, satellite_viewer)
        down = e.get_point()  # record for future translations
        model_transformer_master.translate(transformed_point.x, transformed_point.y)

    def mouse_moved(self, e):
        if not self.is_handling_mouse_events:
            return
        e.consume()
        if self.is_in_satellite_lens_area(e):
            install_cursor(self.cursor, e)
            e.consume()

    def mouse_clicked(self, e):
        if not self.is_handling_mouse_events or not self.check_modifiers(e):
            return
        e.consume()
        reset_state()
        move_master_viewer_to_mouse_point(e)

    def mouse_pressed(self, e):
        if not self.check_modifiers(e) or not self.is_in_satellite_lens_area(e):
            return
        is_handling_mouse_events = True
        down = e.get_point()
        e.consume()

    def mouse_released(self, e):
        if not self.is_handling_mouse_events:
            return
        if not self.did_drag:
            reset_state()
            did_drag = False
            down = None

        satellite_viewer = get_satellite_graph_viewer(e)
        view_master = get_graph_viewer(e)
        satellite_lens = get_satellite_lens_in_satellite_view_space(satellite_viewer, view_master)

        adjusted_lens_point_in_view_space = self.get_lens_point_adjusted_for_satellite_bounds(
            satellite_viewer, satellite_lens
        )
        lens_bounds = satellite_lens.bounds()
        current_lens_point_in_view_space = lens_bounds.location()

        if not should_adjust_lens_point(current_lens_point_in_view_space, adjusted_lens_point_in_view_space, lens_bounds.size()):
            return

        transformed_point = self.get_delta_for_view_space_points_in_layout_space(
            adjusted_lens_point_in_view_space, current_lens_point_in_view_space, satellite_viewer
        )
        model_transformer_master.translate(transformed_point.x, transformed_point.y)

    def should_adjust_lens_point(self, current_lens_point, adjusted_lens_point, size):
        if adjusted_lens_point == current_lens_point:
            return False  # no adjustments needed; lens is completely on the satellite

        x1 = current_lens_point.x
        x2 = adjusted_lens_point.x
        x_difference = max(x1, x2) - min(x1, x2)
        if x_difference > size.width * .66:
            return True

        y1 = current_lens_point.y
        y2 = adjusted_lens_point.y
        y_difference = max(y1, y2) - min(y1, y2)
        return y_difference > size.height * .66

    def get_lens_point_adjusted_for_satellite_bounds(self, satellite_viewer, satellite_lens):
        bounds = satellite_lens.bounds()
        location = bounds.location()
        location = SwingUtilities.convert_point(satellite_viewer, location, satellite_viewer.parent)

        bounds.set_location(location)
        satellite_bounds = satellite_viewer.bounds
        lens_bounds = self.move_rectangle_completely_onto_other_rectangle(bounds, satellite_bounds.bounds())

        return SwingUtilities.convert_point(
            satellite_viewer.parent,
            lens_bounds.location(),
            satellite_viewer
        )

    def move_rectangle_completely_onto_other_rectangle(self, movee_rectangle, destination_rectangle):
        new_rectangle = Rectangle(movee_rectangle)
        new_rectangle.x = min(new_rectangle.x, destination_rectangle.x + destination_rectangle.width - new_rectangle.width - 1)
        new_rectangle.x = max(new_rectangle.x, destination_rectangle.x + 1)

        new_rectangle.y = min(new_rectangle.y, destination_rectangle.y + destination_rectangle.height - new_rectangle.height - 1)
        new_rectangle.y = max(new_rectangle.y, destination_rectangle.y + 1)

        return new_rectangle

    def get_delta_for_view_space_points_in_layout_space(self, new_point_in_view_space, current_point_in_view_space, viewer):
        render_context = viewer.render_context
        multi_layer_transformer = render_context.multi_layer_transformer
        current_point_in_layout_space = multi_layer_transformer.inverse_transform(current_point_in_view_space)
        new_point_in_layout_space = multi_layer_transformer.inverse_transform(new_point_in_view_space)

        dx = (current_point_in_layout_space.x - new_point_in_layout_space.x)
        dy = (current_point_in_layout_space.y - new_point_in_layout_space.y)

        return Point2D.Double(dx, dy)
