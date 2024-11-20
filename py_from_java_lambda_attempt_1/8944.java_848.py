Here is the translation of the Java code into Python:

```Python
import sys
from gi.repository import Gtk

class FilterFormattedTextField(Gtk.Entry):
    def __init__(self, factory, default_value):
        super().__init__()
        self.factory = factory
        self.default_value = default_value
        self.set_text(str(default_value))
        self.current_status = None
        self.is_error = False
        self.ignore_focus_edit_changes = False

        self.connect("notify::text", self.on_notify_text)
        self.connect("focus-out-event", self.on_focus_out)

    def disable_focus_event_processing(self):
        self.ignore_focus_edit_changes = True

    def get_filter_status(self):
        return self.current_status

    def add_filter_status_listener(self, listener):
        if not hasattr(self, 'listeners'):
            self.listeners = []
        self.listeners.append(listener)

    def filter_status_changed(self, status):
        if self.listeners:
            for listener in self.listeners:
                listener.filter_status_changed(status)
        self.current_status = status

    def update_text(self):
        if self.ignore_focus_edit_changes:
            return
        verifier = self.get_input_verifier()
        if verifier and not verifier.verify(self):
            self.is_error = True
        else:
            self.is_error = False
        self.update()

    def set_is_error(self, is_error):
        # only warn if we were not already in an error situation
        if is_error and not self.is_error:
            print("Warning: Error occurred")
        self.is_error = is_error
        self.update()

    def editing_finished(self):
        self.update()

    def has_non_default_value(self):
        default_text = str(self.default_value)
        if default_text == "":
            return False  # not yet initialized

        formatter = self.get_formatter()
        if formatter:
            try:
                value = formatter.string_to_value(self.get_text())
                if value is None:
                    return True  # assume empty string or invalid text
                return not value.equals(self.default_value)
            except Exception as e:
                print(f"Error: {e}")
                return True

    def has_non_default_text(self):
        default_text = str(self.default_value)
        return self.get_text() != default_text

    def update(self):
        color = self.get_current_color()
        if not hasattr(self, 'background'):
            self.background = Gtk.AccelGroup()
        self.set_background(color)

    def get_current_color(self):
        self.update_status()

        # default color
        default_color = "#FFFFFF"
        if self.is_error:
            return "red"  # ERROR_BACKGROUND_COLOR
        elif self.has_non_default_value():
            return "yellow"  # EDITING_BACKGROUND_COLOR

        return default_color

    def update_status(self):
        old_status = self.current_status
        if self.is_error:
            self.current_status = "error"
        elif self.has_non_default_value():
            self.current_status = "applied"
        else:
            self.current_status = None

        if old_status != self.current_status:
            self.filter_status_changed(self.current_status)

    def on_notify_text(self, widget):
        self.update()

    def on_focus_out(self, widget, event):
        self.ignore_focus_edit_changes = True
```

Please note that this is a direct translation of the Java code into Python. The resulting Python code may not be idiomatic or optimized for performance.