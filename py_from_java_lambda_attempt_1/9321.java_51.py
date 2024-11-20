Here is the translation of the Java code into Python:

```Python
class ActionToGuiHelper:
    def __init__(self, window_manager):
        self.window_manager = window_manager

    def add_tool_action(self, action: 'DockingActionIf') -> None:
        self.window_manager.add_tool_action(action)

    def remove_tool_action(self, action: 'DockingActionIf') -> None:
        self.window_manager.remove_tool_action(action)

    def add_local_action(self, provider: object, action: 'DockingActionIf') -> None:
        self.window_manager.add_local_action(provider, action)

    def get_component_actions(self, provider: object) -> iter['DockingActionIf']:
        return self.window_manager.get_component_actions(provider)

    def remove_provider_action(self, provider: object, action: 'DockingActionIf') -> None:
        self.window_manager.remove_provider_action(provider, action)

    def key_bindings_changed(self) -> None:
        self.window_manager.schedule_update()
```

Note that Python does not have a direct equivalent to Java's `package` declaration. Also, the translation of Java's comments into Python is subjective and may vary depending on personal preference.

Also note that in Python, you don't need to declare types for variables or function parameters like you do in Java. The type hinting I used (`'DockingActionIf'`) is just a suggestion about what kind of object the variable should be, but it's not enforced by the language itself.