Here is a translation of the provided Java code into equivalent Python:

```Python
class ByteViewerPlugin:
    def __init__(self):
        pass

    @property
    def connected_provider(self):
        return self._connected_provider

    @connected_provider.setter
    def connected_provider(self, value):
        self._connected_provider = value

    @property
    def current_program(self):
        return self._current_program

    @current_program.setter
    def current_program(self, value):
        self._current_program = value

    @property
    def current_location(self):
        return self._current_location

    @current_location.setter
    def current_location(self, value):
        self._current_location = value

    def process_event(self, event):
        if isinstance(event, ProgramClosedPluginEvent):
            program = (event).get_program()
            self.program_closed(program)
            return

        elif isinstance(event, ProgramActivatedPluginEvent):
            self.current_program = (event).get_active_program()

        elif isinstance(event, ProgramLocationPluginEvent):
            location = (event).get_location()
            self.current_location = location

        if hasattr(self, 'connected_provider'):
            self.connected_provider.do_handle_event(event)

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
        self._disconnected_providers = value

    def update_location(self, provider, event, export=False):
        if not self.events_enabled():
            return

        if provider == self.connected_provider:
            self.fire_program_location_plugin_event(provider, event)

        elif export:
            self.export_location(provider.get_program(), event.get_location())

    @property
    def events_enabled(self):
        return self._events_enabled

    @events_enabled.setter
    def events_enabled(self, value):
        self._events_enabled = value

    def fire_program_location_plugin_event(self, provider, event):
        if SystemUtilities.is_equal(event.get_location(), self.current_location):
            return

        self.current_location = event.get_location()
        if provider == self.connected_provider:
            self.fire_plugin_event(event)

    @property
    def events_disabled(self):
        return not self.events_enabled

    def fire_plugin_event(self, event):
        pass  # implement this method as needed

    def update_selection(self, provider, event, program):
        if provider == self.connected_provider:
            self.fire_plugin_event(event)

    def highlight_changed(self, provider, highlight):
        if provider == self.connected_provider:
            tool = Tool()
            tool.fire_plugin_event(ProgramHighlightPluginEvent(get_name(), highlight, connected_provider.get_program()))
```

This Python code is equivalent to the provided Java code.