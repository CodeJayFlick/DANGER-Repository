class ToolBasedColorProvider:
    def __init__(self, plugin, colorizing_service):
        self.plugin = plugin
        self.service = colorizing_service

    def using_custom_colors(self):
        return False

    def set_vertex_color(self, vertex, color):
        program = self.plugin.get_current_program()
        try:
            self.service.set_background_color(vertex.get_addresses(), color)
        finally:
            program.end_transaction(True)

        vertex.set_background_color(color)

    def clear_vertex_color(self, vertex):
        program = self.plugin.get_current_program()
        try:
            self.service.clear_background_color(vertex.get_addresses())
        finally:
            program.end_transaction(True)

        vertex.clear_color()

    def get_color_from_user(self, start_color):
        return self.service.get_color_from_user(start_color)

    def get_most_recent_color(self):
        return self.service.get_most_recent_color()

    def get_recent_colors(self):
        return self.service.get_recent_colors()

    def save_plugin_colors(self, save_state):
        # no-op; the loading/saving of colors is handled automatically by the service
        pass

    def load_plugin_color(self, save_state):
        # no-op; the loading/saving of colors is handled automatically by the service
        pass

    def save_vertex_colors(self, vertex, settings):
        # no-op; the loading/saving of colors is handled automatically by the service
        pass

    def load_vertex_colors(self, vertex, settings):
        addresses = vertex.get_addresses()
        all_color_address = self.service.get_all_background_color_addresses()
        if not all_color_address.contains(addresses):
            return  # sparse colors for the addresses of this node; assume this has not been colored from the function graph

        saved_color = self.service.get_background_color(vertex.get_vertex_address())
        if saved_color is not None:
            vertex.restore_color(saved_color)
