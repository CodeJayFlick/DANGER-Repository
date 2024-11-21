class DecompilePlugin:
    def __init__(self):
        self.connected_provider = None
        self.disconnected_providers = []
        self.current_program = None
        self.current_location = None
        self.current_selection = None

    def delayed_location_update(self, func):
        if self.current_location is not None:
            self.connected_provider.set_location(self.current_location, None)
        SwingUpdateManager().update_later(func)

    def init(self):
        clipboard_service = tool.get_clipboard_service()
        if clipboard_service is not None:
            self.connected_provider.set_clipboard_service(clipboard_service)
            for provider in self.disconnected_providers:
                provider.set_clipboard_service(clipboard_service)

    def write_data_state(self, save_state):
        if self.connected_provider is not None:
            self.connected_provider.write_data_state(save_state)
        save_state.put_int("Num Disconnected", len(self.disconnected_providers))
        i = 0
        for provider in self.disconnected_providers:
            provider_save_state = SaveState()
            df = provider.get_program().get_domain_file()
            if df.get_parent() is not None:
                continue
            program_pathname = df.get_pathname()
            provider_save_state.put_string("Program Path", program_pathname)
            provider.write_data_state(provider_save_state)
            element_name = "Provider" + str(i)
            save_state.put_xml_element(element_name, provider_save_state.save_to_xml())
            i += 1

    def read_data_state(self, save_state):
        if self.connected_provider is not None:
            self.connected_provider.read_data_state(save_state)

        num_disconnected = save_state.get_int("Num Disconnected", 0)
        for _ in range(num_disconnected):
            xml_element = save_state.get_xml_element("Provider" + str(i))
            provider_save_state = SaveState(xml_element)
            program_path = provider_save_state.get_string("Program Path")
            file = tool.get_project().get_file(program_path)
            if file is not None:
                program = tool.get_program_manager().open_program(file)
                if program is not None:
                    new_provider = self.create_new_disconnected_provider()
                    new_provider.set_program(program)
                    new_provider.read_data_state(provider_save_state)

    def create_new_disconnected_provider(self):
        provider = DecompilerProvider(self, False)
        provider.set_clipboard_service(tool.get_clipboard_service())
        self.disconnected_providers.append(provider)
        tool.show_component_provider(provider, True)
        return provider

    def dispose(self):
        if self.connected_provider is not None:
            remove_provider(self.connected_provider)

        for provider in self.disconnected_providers:
            remove_provider(provider)

        self.disconnected_providers.clear()

    def export_location(self, program, location):
        service = tool.get_goto_service()
        if service is not None:
            service.goto(location, program)

    def update_selection(self, provider, sel_program, selection):
        if provider == self.connected_provider:
            fire_plugin_event(PluginEvent(ProgramSelectionPluginEvent(name, selection, sel_program)))

    def close_provider(self, provider):
        if provider == self.connected_provider:
            tool.show_component_provider(provider, False)
        else:
            self.disconnected_providers.remove(provider)
            remove_provider(provider)

    def location_changed(self, provider, location):
        if provider == self.connected_provider:
            fire_plugin_event(PluginEvent(ProgramLocationPluginEvent(name, location, location.get_program())))

    def selection_changed(self, provider, selection):
        if provider == self.connected_provider:
            fire_plugin_event(PluginEvent(ProgramSelectionPluginEvent(name, selection, current_program)))

    def process_event(self, event):
        if isinstance(event, ProgramClosedPluginEvent):
            program = event.get_program()
            self.program_closed(program)
            return

        if self.connected_provider is None:
            return

        if isinstance(event, ProgramActivatedPluginEvent):
            self.current_program = event.get_active_program()
            self.connected_provider.set_program(self.current_program)

    def program_closed(self, closed_program):
        for provider in self.disconnected_providers:
            if provider.get_program() == closed_program:
                self.disconnected_providers.remove(provider)
                remove_provider(provider)

        if self.connected_provider is not None:
            self.connected_provider.program_closed(closed_program)

    def get_current_location(self):
        return self.current_location

class DecompilerProvider:
    def __init__(self, plugin, disconnected):
        self.plugin = plugin
        self.disconnected = disconnected
        self.clipboard_service = None
        self.set_clipboard_service(None)
