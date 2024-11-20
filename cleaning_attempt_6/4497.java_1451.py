class ProgramPlugin:
    def __init__(self):
        self.current_program = None
        self.current_location = None
        self.current_selection = None
        self.current_highlight = None
        self.program_action_list = []
        self.location_action_list = []
        self.selection_action_list = []
        self.highlight_action_list = []

    def process_event(self, event):
        if isinstance(event, ProgramClosedEvent):
            program_closed(event.get_program())
        elif isinstance(event, ProgramOpenedEvent):
            program_opened(event.get_program())
        elif isinstance(event, ProgramActivatedEvent):
            old_program = self.current_program
            self.current_program = event.get_active_program()
            if old_program is not None:
                program_deactivated(old_program)
                self.current_location = None
                self.current_selection = None
                self.current_highlight = None
                location_changed(None)
                selection_changed(None)
                highlight_changed(None)
                enable_actions(self.location_action_list, False)
                enable_actions(self.selection_action_list, False)
                enable_actions(self.highlight_action_list, False)
            if self.current_program is not None:
                program_activated(self.current_program)
            enable_actions(self.program_action_list, self.current_program is not None)

        elif isinstance(event, ProgramLocationEvent):
            self.current_location = event.get_location()
            if self.current_location is not None and self.current_location.address == null or (self.current_program is None and event.get_program() is None):
                self.current_location = None
                enable_actions(self.location_action_list, False)
            elif self.current_location is None:
                disable_actions(self.location_action_list)
            else:
                enable_actions(self.location_action_list, True)

        elif isinstance(event, ProgramSelectionEvent):
            self.current_selection = event.get_selection()
            if self.current_selection is not None and len(self.current_selection) > 0:
                enable_actions(self.selection_action_list, True)
            else:
                disable_actions(self.selection_action_list)

        elif isinstance(event, ProgramHighlightEvent):
            self.current_highlight = event.get_highlight()
            if self.current_highlight is not None and len(self.current_highlight) > 0:
                enable_actions(self.highlight_action_list, True)
            else:
                disable_actions(self.highlight_action_list)

    def program_activated(self, program):
        pass

    def program_closed(self, program):
        pass

    def program_opened(self, program):
        pass

    def location_changed(self, loc):
        pass

    def selection_changed(self, sel):
        pass

    def highlight_changed(self, hl):
        pass

    def enable_actions(self, list, enabled):
        for action in list:
            action.set_enabled(enabled)

    def go_to(self, addr):
        service = self.tool.get_service(GoToService)
        if service is not None:
            return service.go_to(addr)
        return False

    def set_selection(self, set):
        if self.current_program is not None:
            fire_plugin_event(ProgramSelectionEvent(self.name, ProgramSelection(set), self.current_program))

    def set_bookmark(self, addr, type, category, comment):
        if self.current_program is not None:
            bookmark_manager = self.current_program.get_bookmark_manager()
            transaction_id = self.current_program.start_transaction("Set Bookmark")
            try:
                bookmark_manager.set_bookmark(addr, type, category, comment)
            finally:
                self.current_program.end_transaction(transaction_id, True)

    def disable_actions(self, list):
        for action in list:
            action.set_enabled(False)
