Here is the translation of the Java code into Python:

```Python
class AbstractActionBuilder:
    def __init__(self):
        self.name = None
        self.owner = None
        self.action_context_class = ActionContext
        self.supports_default_tool_context = False
        self.window_when = When.MAIN_WINDOW

    def description(self, text: str) -> 'AbstractActionBuilder':
        self.description = text
        return self

    def enabled(self, b: bool) -> 'AbstractActionBuilder':
        self.is_enabled = b
        return self

    def shared_key_binding(self) -> 'AbstractActionBuilder':
        self.key_binding_type = KeyBindingType.SHARED
        return self

    def help_location(self, location: HelpLocation) -> 'AbstractActionBuilder':
        self.help_location = location
        return self

    def menu_path(self, path: str) -> 'AbstractActionBuilder':
        self.menu_path = [path]
        return self

    def menu_group(self, group: str) -> 'AbstractActionBuilder':
        self.menu_group = group
        return self

    def menu_subgroup(self, subgroup: str) -> 'AbstractActionBuilder':
        self.menu_subgroup = subgroup
        return self

    def menu_icon(self, icon: Icon) -> 'AbstractActionBuilder':
        self.menu_icon = icon
        return self

    def popup_menu_path(self, path: str) -> 'AbstractActionBuilder':
        self.popup_path = [path]
        return self

    def popup_group(self, group: str) -> 'AbstractActionBuilder':
        self.popup_group = group
        return self

    def popup_subgroup(self, subgroup: str) -> 'AbstractActionBuilder':
        self.popup_subgroup = subgroup
        return self

    def popup_icon(self, icon: Icon) -> 'AbstractActionBuilder':
        self.popup_icon = icon
        return self

    def tool_bar_icon(self, icon: Icon) -> 'AbstractActionBuilder':
        self.toolbar_icon = icon
        return self

    def key_binding(self, binding: KeyStroke) -> 'AbstractActionBuilder':
        self.key_binding = binding
        return self

    def on_action(self, callback: Consumer[ActionContext]) -> 'AbstractActionBuilder':
        self.action_callback = callback
        return self

    def valid_context_when(self, predicate: Predicate[ActionContext]) -> 'AbstractActionBuilder':
        self.valid_context_predicate = predicate
        return self

    def popup_when(self, predicate: Predicate[ActionContext]) -> 'AbstractActionBuilder':
        self.popup_predicate = predicate
        return self

    def in_window(self, when: When) -> 'AbstractActionBuilder':
        self.window_when = when
        return self

    @property
    def is_popup_action(self):
        return len(self.menu_path) > 0

    @property
    def is_toolbar_action(self):
        return self.toolbar_icon is not None

    @property
    def is_menu_action(self):
        return len(self.menu_path) > 0

    @property
    def is_key_binding_action(self):
        return self.key_binding is not None

    def build(self, name: str = '', owner: str = '') -> 'AbstractActionBuilder':
        action = DockingAction()
        if self.is_popup_action():
            action.popup_menu_path = [path]
        elif self.is_toolbar_action():
            action.toolbar_icon = icon
        else:
            action.menu_path = path

    def build_and_install(self, tool: Tool) -> None:
        pass