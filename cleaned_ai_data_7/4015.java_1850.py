class MarkerManagerPlugin:
    def __init__(self):
        self.code_viewer_service = None
        self.marker_manager = None
        self.program = None

    def start(self, tool):
        super().__init__()
        self.marker_manager = MarkerManager(self)
        options = tool.get_options("CATEGORY_BROWSER_NAVIGATION_MARKERS")
        help_location = HelpLocation(HelpTopics.CODE_BROWSER, "CATEGORY_BROWSER_NAVIGATION_MARKERS")
        options.set_help_location(help_location)

    def stop(self):
        if self.code_viewer_service:
            self.code_viewer_service.remove_margin_provider(self.marker_manager.get_margin_provider())
            self.code_viewer_service.remove_overview_provider(self.marker_manager.get_overview_provider())

        self.marker_manager.stop()

    def process_event(self, event):
        if isinstance(event, ProgramActivatedPluginEvent):
            program = (event).get_active_program()
            old_program = self.program
            self.program = program

            if old_program:
                self.marker_manager.set_program(None)
            elif program:
                self.marker_manager.set_program(program)

        elif isinstance(event, ProgramClosedPluginEvent):
            self.marker_manager.program_closed((event).get_program())

class MarkerManager:
    def __init__(self, plugin):
        self.plugin = plugin

    def get_margin_provider(self):
        # TO DO: implement margin provider
        pass

    def get_overview_provider(self):
        # TO DO: implement overview provider
        pass

    def set_program(self, program):
        self.program = program

    def stop(self):
        pass

class ProgramActivatedPluginEvent:
    def __init__(self, active_program):
        self.active_program = active_program

class ProgramClosedPluginEvent:
    def __init__(self, program):
        self.program = program
