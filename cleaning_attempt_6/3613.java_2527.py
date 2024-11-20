class ConsolePlugin:
    def __init__(self):
        self.provider = None

    def start(self, tool):
        super().__init__()
        self.provider = ConsoleComponentProvider(tool)
        tool.register_service(ConsoleService, self.provider)

    def init(self):
        super().init()
        if self.provider is not None:
            self.provider.init()

    def dispose(self):
        super().dispose()
        if self.provider is not None:
            self.provider.dispose()

    def program_activated(self, program):
        if self.provider is not None:
            self.provider.set_current_program(program)

    def program_deactivated(self, program):
        if self.provider is not None:
            self.provider.set_current_program(None)

    def process_event(self, event):
        super().process_event(event)
        if isinstance(event, ProgramLocationPluginEvent):
            plpe = event
            location = plpe.get_location()
            address = location.get_address()
            if self.provider is not None:
                self.provider.set_current_address(address)


class ConsoleComponentProvider:
    def __init__(self, tool):
        pass

    def init(self):
        pass

    def dispose(self):
        pass

    def set_current_program(self, program):
        pass

    def set_current_address(self, address):
        pass
