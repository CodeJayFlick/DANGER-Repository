class SubToolContext:
    def __init__(self, plugin):
        self.plugin = plugin
        self.tool_manager = plugin.get_tool_manager()
        self.match = None

    @property
    def source_function(self):
        return self.tool_manager.source_function()

    @property
    def destination_function(self):
        return self.tool_manager.destination_function()

    def is_source_cursor_on_screen(self):
        return self.tool_manager.is_source_cursor_on_screen()

    def is_destination_cursor_on_screen(self):
        return self.tool_manager.is_destination_cursor_on_screen()

    @property
    def match(self):
        if self.match is None:
            self.match = get_existing_match(
                self.source_function, self.destination_function)
        return self.match

def get_existing_match(source_function, destination_function):
    if source_function is None or destination_function is None:
        return None

    source_address = source_function.entry_point
    destination_address = destination_function.entry_point
    controller = plugin.get_controller()
    session = controller.session
    match_sets = session.match_sets
    for match_set in match_sets:
        matches = match_set.matches(source_address, destination_address)
        for next_match in matches:
            return next_match

    return None
