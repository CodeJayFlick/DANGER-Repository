class ViewManagerComponentProvider:
    OLD_NAME = "ProgramTreePlugin"
    NAME = "Program Tree"

    CURRENT_VIEW = "Current Viewname"

    def __init__(self, tool, owner):
        self.view_panel = None
        self.listeners = []
        self.current_program = None
        self.restored_view_name = None

        super().__init__(tool, self.NAME, owner)

        self.view_panel = ViewPanel(self.tool, self)
        self.listeners = []

        self.set_title("Program Trees")
        self.set_help_location(HelpLocation(owner, self.get_name()))
        self.set_default_window_position(WindowPosition.LEFT)

    def service_added(self, service):
        if not isinstance(service, ViewProviderService):
            return

        self.view_panel.add_view(service)
        view_name = service.get_view_name()
        if view_name == self.restored_view_name:
            self.restored_view_name = None
            self.view_panel.set_current_view(view_name)

    def service_removed(self, service):
        if not isinstance(service, ViewProviderService):
            return

        self.view_panel.remove_view(service)

    def add_view_change_listener(self, listener):
        if listener in self.listeners:
            return

        self.listeners.append(listener)

    def remove_view_change_listener(self, listener):
        try:
            self.listeners.remove(listener)
        except ValueError:
            pass  # The list did not contain the element.

    def add_to_view(self, loc):
        return self.view_panel.add_to_view(loc)

    def get_current_view(self):
        return self.view_panel.get_current_view()

    def view_changed(self, addr_set):
        for listener in self.listeners[:]:
            try:
                listener.view_changed(addr_set)
            except Exception as e:
                print(f"Error: {e}")

    def view_name_changed(self, vps, old_name):
        self.view_panel.view_name_changed(vps, old_name)

    def set_current_view_provider(self, vps):
        if not isinstance(vps, ViewProviderService):
            return

        self.view_panel.set_current_view(vps.get_view_name())

    def dispose(self):
        self.view_panel.dispose()
        self.listeners.clear()

    def write_data_state(self, save_state):
        view_name = self.view_panel.get_current_view_name()
        if view_name:
            save_state.put_string(ViewManagerComponentProvider.CURRENT_VIEW, view_name)

    def read_data_state(self, save_state):
        if not isinstance(save_state, SaveState) or not hasattr(save_state, 'get'):
            return

        restored_view_name = save_state.get_string(ViewManagerComponentProvider.CURRENT_VIEW)
        self.view_panel.set_current_view(restored_view_name)

    def get_undo_redo_state(self, domain_object):
        state = SaveState()
        self.write_data_state(state)
        return state

    def restore_undo_redo_state(self, domain_object, state):
        if not isinstance(state, SaveState) or not hasattr(save_state, 'get'):
            return

        self.read_data_state(state)

class ViewPanel:
    def __init__(self, tool, provider):
        pass  # This class is not implemented in the provided Java code.

class HelpLocation:
    def __init__(self, owner, name):
        pass  # This class is not implemented in the provided Java code.

class WindowPosition:
    LEFT = None

class ViewProviderService:
    def get_view_name(self):
        return None  # This method should be overridden by a subclass.

    def add_to_view(self, loc):
        return None  # This method should be overridden by a subclass.

    def remove_view(self, service):
        pass  # This class is not implemented in the provided Java code.
