Here is a translation of the Java code into equivalent Python:

```Python
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
```

Please note that Python does not have direct equivalent of Java's package and import statements. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass; this concept doesn't exist in Python as it uses duck typing instead.

The code also assumes that you have classes like ApplicationInformationDisplayFactory, DockingWindowManager, ToolActions, ActionToGuiHelper and options_map defined elsewhere.