Here is the translation of the Java code into Python:

```Python
class CodeBrowserPlugin:
    def __init__(self, tool):
        self.connected_provider = None
        self.current_program = None
        self.view_manager = None
        super().__init__()

    @property
    def connected_provider(self):
        return self._connected_provider

    @connected_provider.setter
    def connected_provider(self, value):
        if not isinstance(value, CodeViewerProvider):
            raise TypeError("Connected provider must be an instance of CodeViewerProvider")
        self._connected_provider = value

    @property
    def current_program(self):
        return self._current_program

    @current_program.setter
    def current_program(self, value):
        if not isinstance(value, Program) and value is not None:
            raise TypeError("Current program must be an instance of Program or None")
        self._current_program = value

    @property
    def view_manager(self):
        return self._view_manager

    @view_manager.setter
    def view_manager(self, value):
        if not isinstance(value, ViewManagerService) and value is not None:
            raise TypeError("View manager must be an instance of ViewManagerService or None")
        self._view_manager = value

    def highlight_changed(self, provider, highlight):
        markers = get_highlight_markers(self.current_program)
        if markers is not None:
            markers.clear_all()
        if highlight is not None and self.current_program is not None:
            if markers is not None:
                markers.add(highlight)
        if provider == self.connected_provider:
            tool.fire_plugin_event(ProgramHighlightPluginEvent(provider.get_name(), highlight, provider.get_program()))

    def process_event(self, event):
        if isinstance(event, ProgramClosedPluginEvent):
            program = (ProgramClosedPluginEvent)event).get_program()
            self.program_closed(program)
            return
        elif isinstance(event, ProgramActivatedPluginEvent):
            if self.current_program is not None:
                self.current_program.remove_listener(self)
            active_program = event.get_active_program()
            if active_program is not None:
                self.current_program = active_program
                self.current_program.add_listener(self)
            else:
                self.current_view = AddressSet()
        elif isinstance(event, ProgramLocationPluginEvent):
            location = (ProgramLocationPluginEvent)event).get_location()
            if not self.connected_provider.set_location(location):
                view_manager = self.view_manager
                connected_provider = self.connected_provider
                listing_panel = connected_provider.get_listing_panel()
                listing_panel.go_to(location, True)
        elif isinstance(event, ProgramSelectionPluginEvent):
            selection = event.get_selection()
            self.selection_changed(selection)

    def program_closed(self, closed_program):
        for provider in self.disconnected_providers:
            if provider.get_program() == closed_program:
                self.disconnected_providers.remove(provider)
                self.remove_provider(provider)

    @property
    def disconnected_providers(self):
        return self._disconnected_providers

    @disconnected_providers.setter
    def disconnected_providers(self, value):
        if not isinstance(value, list) and value is not None:
            raise TypeError("Disconnected providers must be a list or None")
        self._disconnected_providers = value

    def get_transient_state(self):
        state = [self.connected_provider.get_viewer_position(), 
                 self.connected_provider.get_location(),
                 self.connected_provider.get_highlight(),
                 self.connected_provider.get_selection(),
                 self.current_view]
        return state

    def restore_transient_state(self, object_state):
        state = (object_state)
        viewer_position = state[0]
        location = state[1]
        highlight = state[2]
        selection = state[3]

        view_changed((AddressSetView)state[4])

        if location is not None:
            self.connected_provider.set_location(location)

        self.highlight_changed(self.connected_provider, highlight)
        if selection is not None:
            self.selection_changed(selection)
        viewer_position_vp = state[0]
        field_panel = connected_provider.get_listing_panel().get_field_panel()
        field_panel.set_viewer_position(viewer_position_vp.get_index(), 
                                         viewer_position_vp.get_x_offset(),
                                         viewer_position_vp.get_y_offset())

    def write_data_state(self, save_state):
        if self.connected_provider is not None:
            self.connected_provider.write_data_state(save_state)
        num_disconnected = len(self.disconnected_providers)

        for i in range(num_disconnected):
            provider_save_state = SaveState()
            program_pathname = disconnected_providers[i].get_program().get_domain_file().get_pathname()
            provider.save_state(provider_save_state, program_pathname)
            element_name = "Provider" + str(i)
            save_state.put_xml_element(element_name, provider_save_state.save_to_xml())

        highlight = self.connected_provider.get_listing_panel().get_field_panel().get_highlight()
        highlight.save(save_state)

    def read_data_state(self, save_state):
        program_manager_service = tool.get_service(ProgramManagerService.class)

        if self.connected_provider is not None:
            self.connected_provider.read_data_state(save_state)
        num_disconnected = len(self.disconnected_providers)

        for i in range(num_disconnected):
            xml_element = save_state.get_xml_element("Provider" + str(i))
            provider_save_state = SaveState(xml_element)
            program_pathname = provider_save_state.get_string("Program Path", "")
            file = tool.get_project().get_project_data().get_file(program_pathname)

            if file is not None:
                program = program_manager_service.open_program(file)
                if program is not None:
                    provider = CodeViewerProvider(self, format_mgr, False)
                    provider.do_set_program(program)
                    provider.read_data_state(provider_save_state)

        highlight = FieldSelection()
        highlight.load(save_state)
        if not highlight.is_empty():
            self.set_highlight(highlight)

    def write_config_state(self, save_state):
        self.format_mgr.save_state(save_state)
        self.connected_provider.save_state(save_state)

    def read_config_state(self, save_state):
        self.format_mgr.read_state(save_state)
        self.connected_provider.read_state(save_state)

    def location_changed(self, provider, location):
        if provider == self.connected_provider:
            cursor_markers = get_cursor_markers(self.current_program)
            if cursor_markers is not None:
                cursor_markers.clear_all()
                cursor_markers.add(location.get_address())
            tool.fire_plugin_event(ProgramLocationPluginEvent(provider.get_name(), 
                                                                 location,
                                                                 provider.get_program()))

    def get_view_manager(self, code_viewer_provider):
        if code_viewer_provider == self.connected_provider:
            return self.view_manager
        else:
            return None

class CodeViewerProvider:
    pass

class ProgramManagerService:
    pass

class ViewManagerService:
    pass

class AddressSetView:
    pass

class FieldSelection:
    def __init__(self):
        self._highlight = []

    @property
    def highlight(self):
        return self._highlight

    @highlight.setter
    def highlight(self, value):
        if not isinstance(value, list) and value is not None:
            raise TypeError("Highlight must be a list or None")
        self._highlight = value

    def save(self, save_state):
        pass

    def load(self, save_state):
        pass

class MarkerSet:
    def __init__(self):
        self._markers = []

    @property
    def markers(self):
        return self._markers

    @markers.setter
    def markers(self, value):
        if not isinstance(value, list) and value is not None:
            raise TypeError("Markers must be a list or None")
        self._markers = value

    def clear_all(self):
        pass

    def add(self, marker):
        pass