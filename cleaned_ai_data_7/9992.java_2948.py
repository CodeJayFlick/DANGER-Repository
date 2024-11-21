class FakeDockingTool:
    def __init__(self):
        window_icons = ApplicationInformationDisplayFactory.get_window_icons()
        self.win_mgr = DockingWindowManager(self, window_icons, False, True, True, None)
        self.tool_actions = ToolActions(self, ActionToGuiHelper(self.win_mgr))

    @property
    def name(self) -> str:
        return "Fake Tool"

    @property
    def icon(self):
        return None

    def get_options(self, category: str) -> dict:
        opt = options_map.get(category)
        if opt is None:
            opt = {"category": category}
            options_map[category] = opt
        return opt

    def close(self):
        pass  # stub

    def get_service(self, service_class: type) -> object:
        return None

    def add_service_listener(self, listener: callable):
        pass  # stub

    def remove_service_listener(self, listener: callable):
        pass  # stub

    @property
    def default_tool_context(self) -> dict:
        return {}
