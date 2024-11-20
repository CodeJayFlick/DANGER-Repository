Here is the translation of the Java code into Python:

```Python
class GTreeSelectionModel:
    def __init__(self):
        self.listeners = []
        self.current_event_origin = "USER_GENERATED"

    def add_g_tree_selection_listener(self, listener):
        if listener not in self.listeners:
            self.listeners.append(listener)

    def remove_g_tree_selection_listener(self, listener):
        try:
            self.listeners.remove(listener)
        except ValueError:
            pass

    def fire_value_changed(self, event):
        for listener in self.listeners:
            listener.value_changed(event)

    def set_current_event_origin(self, origin):
        if origin not in ["USER_GENERATED", "INTERNAL_GENERATED"]:
            raise Exception("Invalid Event Origin")
        self.current_event_origin = origin

    def clear_selection(self):
        self.set_current_event_origin("INTERNAL_GENERATED")
        super().clear_selection()
        self.set_current_event_origin("USER_GENERATED")

    def remove_selection_paths(self, paths):
        self.set_current_event_origin("INTERNAL_GENERATED")
        super().remove_selection_paths(paths)
        self.set_current_event_origin("USER_GENERATED")

    def user_removed_selection_path(self, path):
        self.set_current_event_origin("USER_GENERATED")
        super().remove_selection_paths([path])
        self.set_current_event_origin("USER_GENERATED")

class GTreeSelectionEvent:
    def __init__(self, event, origin):
        self.event = event
        self.origin = origin

    def get_event_origin(self):
        return self.origin


# Example usage:

class MyGTreeSelectionListener:
    def value_changed(self, event):
        if event.get_event_origin() == "USER_GENERATED":
            print("User generated selection change")
        else:
            print("Internal code triggered the selection change")


if __name__ == "__main__":
    model = GTreeSelectionModel()
    listener = MyGTreeSelectionListener()

    # Add and remove listeners
    model.add_g_tree_selection_listener(listener)
    model.remove_g_tree_selection_listener(listener)

    # Test methods
    event = GTreeSelectionEvent(None, "USER_GENERATED")
    model.fire_value_changed(event)

    model.clear_selection()
    model.user_removed_selection_path(TreePath("path"))
```

Please note that Python does not have direct equivalent of Java's `ArrayList` and `DefaultTreeSelectionModel`. I used a list to simulate the behavior of an ArrayList. Also, there is no built-in class like DefaultTreeSelectionModel in Python, so we can't directly extend it.