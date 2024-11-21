import ghidra_app

class ReferenceListingHoverPlugin:
    def __init__(self, tool):
        super().__init__(tool)
        self.reference_hover_service = ReferenceListingHover(tool)

    def init(self):
        # The ReferenceHover is dependent on the CodeFormatService.
        pass

    def process_event(self, event):
        if isinstance(event, ProgramClosedPluginEvent):
            program_closed_event = event
            self.reference_hover_service.program_closed(program_closed_event.get_program())

    def dispose(self):
        self.reference_hover_service.dispose()

class ReferenceListingHover:
    def __init__(self, tool):
        pass

    def program_closed(self, program):
        pass

# Register the plugin with Ghidra
ghidra_app.register_plugin(ReferenceListingHoverPlugin)
