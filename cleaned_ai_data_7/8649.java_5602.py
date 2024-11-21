class DiffNavigatable:
    def __init__(self, diff_plugin, navigatable):
        self.diff_plugin = diff_plugin
        self.navigatable = navigatable
        self.disposed = False
        self.navigation_listeners = set()

    def go_to(self, program, location):
        return self.navigatable.go_to(program, location)

    def get_location(self):
        return self.navigatable.get_location()

    def get_program(self):
        return self.diff_plugin.second_program

    def get_memento(self):
        cursor_offset = self.diff_plugin.listing_panel.field_panel.cursor_offset
        memento = CodeViewerLocationMemento(
            self.diff_plugin.second_program, 
            self.diff_plugin.current_location, 
            cursor_offset)
        return memento

    def set_memento(self, memento):
        cv_memento = CodeViewerLocationMemento(memento)
        cursor_offset = cv_memento.cursor_offset
        self.diff_plugin.listing_panel.field_panel.position_cursor(cursor_offset)

    def get_navigatable_icon(self):
        return self.navigatable.get_navigatable_icon()

    def is_connected(self):
        return True

    def supports_markers(self):
        return self.is_connected()

    def request_focus(self):
        self.diff_plugin.listing_panel.field_panel.request_focus()

    def is_visible(self):
        return (self.navigatable.is_visible() and 
                self.diff_plugin.showing_diff)

    def get_instance_id(self):
        return self.navigatable.get_instance_id()

    def set_selection(self, selection):
        if not selection:
            selection = ProgramSelection()
        self.diff_plugin.set_program2_selection(selection)

    def set_highlight(self, highlight):
        pass  # The right-hand Diff listing doesn't currently support highlight.

    def get_selection(self):
        return self.navigatable.get_selection()

    def get_highlight(self):
        return self.navigatable.get_highlight()

    def get_text_selection(self):
        return self.navigatable.get_text_selection()

    def add_navigatable_listener(self, listener):
        self.navigation_listeners.add(listener)

    def remove_navigatable_listener(self, listener):
        self.navigation_listeners.remove(listener)

    def dispose(self):
        self.disposed = True
        for listener in self.navigation_listeners:
            listener.navigatable_removed(self)
