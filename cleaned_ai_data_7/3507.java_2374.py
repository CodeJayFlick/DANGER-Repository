class CodeBrowserPluginInterface:
    def get_tool(self):
        pass  # Implement this method in your subclass

    def get_name(self):
        pass  # Implement this method in your subclass

    def provider_closed(self, code_viewer_provider):
        pass  # Implement this method in your subclass

    def is_disposed(self):
        return False  # Default implementation: the plugin is not disposed

    def location_changed(self, code_viewer_provider, program_location):
        pass  # Implement this method in your subclass

    def selection_changed(self, code_viewer_provider, current_selection):
        pass  # Implement this method in your subclass

    def highlight_changed(self, code_viewer_provider, highlight):
        pass  # Implement this method in your subclass

    def get_view_manager(self, code_viewer_provider):
        pass  # Implement this method in your subclass

    def create_new_disconnected_provider(self):
        return None  # Default implementation: returns None
