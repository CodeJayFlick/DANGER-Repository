Here is the translation of the given Java code into Python:

```Python
class SymbolTreePlugin:
    PLUGIN_NAME = "SymbolTreePlugin"

    def __init__(self):
        self.provider = None
        self.program = None
        self.go_to_service = None
        self.processing_go_to = False

    def process_event(self, event):
        if isinstance(event, ProgramActivatedPluginEvent):
            old_program = self.program
            self.program = event.get_active_program()
            if old_program is not None:
                self.provider.program_deactivated(old_program)
            if self.program is not None:
                self.provider.program_activated(self.program)

        elif isinstance(event, ProgramClosedPluginEvent):
            self.provider.program_closed((event).get_program())

        elif isinstance(event, ProgramLocationPluginEvent):
            if self.processing_go_to:
                return  # no bouncing!!
            location = (event).get_location()
            self.provider.location_changed(location)

    def init(self):
        self.go_to_service = self.tool.get_service(GoToService)
        
    def dispose(self):
        self.tool.remove_component_provider(self.provider)
        self.provider.dispose()
        self.program = None

    def read_config_state(self, save_state):
        self.provider.read_config_state(save_state)

    def write_config_state(self, save_state):
        self.provider.write_config_state(save_state)

    def go_to(self, symbol):
        if isinstance(symbol.get_symbol_type(), SymbolType) and not symbol.get_symbol_type().is_namespace() or symbol.get_symbol_type() == SymbolType.FUNCTION:
            return  # Can't navigate to this type of symbol
        success = False
        reason = ""
        if self.go_to_service is not None:
            try:
                location = symbol.get_program_location()
                if symbol.get_address().is_external_address():
                    self.go_to_service.go_to(symbol.get_address(), self.program)
                    return  # let GoTo service provide status messages
                elif location is not None:
                    reason = " (not in-memory)"
                    success = self.go_to_service.go_to(location)
            finally:
                self.processing_go_to = False

        if not success:
            print(f"Can't navigate to {symbol.get_symbol_type()} symbol: {symbol.get_name()}{reason}")

    def go_to(self, external_location):
        self.go_to_service.go_to_external_location(external_location, False)

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, value):
        self._provider = value
```

Please note that Python does not support direct translation of Java code into Python. This is because the two languages have different syntax and semantics.