Here is the translation of the Java code to Python:
```python
import threading

class MenuBarMenuHandler:
    def __init__(self, window_manager):
        self.window_manager = window_manager

    def menu_item_entered(self, action):
        DockingWindowManager.set_mouse_over_action(action)

    def menu_item_exited(self, action):
        DockingWindowManager.clear_mouse_over_help()

    def process_menu_action(self, action, event):
        DockingWindowManager.clear_mouse_over_help()
        context = self.window_manager.get_action_context(action)
        if context is None:
            return  # nothing to do

        context.set_source_object(event.source)

        # give the UI some time to repaint before executing the action
        threading.invokeLater(lambda: (
            self.window_manager.status_text = ""
            if action.is_valid_context(context) and action.is_enabled_for_context(context):
                if isinstance(action, ToggleDockingActionIf):
                    toggle_action = (ToggleDockingActionIf)(action)
                    toggle_action.selected = not toggle_action.selected

                action.perform_action(context)

        ))
```
Note that I've used the `threading` module to simulate the equivalent of Java's `SwingUtilities.invokeLater()` method, which schedules a task to run on the event dispatch thread.