class ProgramByteViewerComponentProvider:
    def __init__(self, tool, plugin):
        self.is_connected = False
        self.disposed = False
        self.navigatable_icon = None
        self.decoration_component = None
        self.clipboard_service = None
        self.clipboard_provider = None

    def create_program_actions(self):
        # code omitted for brevity
        pass

    def is_snapshot(self):
        return not self.is_connected()

    def get_component(self):
        return self.decoration_component

    def window_group(self):
        if self.is_connected():
            return ""
        else:
            return "disconnected"

    def component_shown(self):
        # code omitted for brevity
        pass

    def action_context(self, event):
        return self.get_byte_viewer_action_context()

    def get_byte_viewer_action_context(self):
        info = self.panel.cursor_location()
        if info is None:
            return None
        return ByteViewerActionContext(self)

    def close_component(self):
        # code omitted for brevity
        pass

    def set_selection(self, selection):
        self.current_selection = selection
        if not tool.is_visible(self):
            return
        block_set.block_selection(block_set.get_block_selection(selection))
        clipboard_provider.set_selection(current_selection)
        panel.set_viewer_selection(block_set.get_block_selection(selection))

    def get_selection(self):
        return current_selection

    # ... and so on for the rest of the methods ...
