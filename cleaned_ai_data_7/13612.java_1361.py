class GhidraScriptEditorPreferencePage:
    def __init__(self):
        self.enabled_field = None
        self.port_field = None
        self.previous_enabled_string = None
        self.current_enabled_string = None
        self.previous_port_string = None
        self.current_port_string = None

    def init(self, workbench):
        pass  # equivalent to setPreferenceStore(Activator.getDefault().getPreferenceStore())

    def create_field_editors(self):
        from gi.repository import GLib
        self.enabled_field = BooleanFieldEditor("Enabled", "Enabled")
        self.port_field = StringFieldEditor("Port Number", "Port:")
        return [self.enabled_field, self.port_field]

    def check_state(self):
        if not self.is_valid():
            return  # equivalent to super.checkState()
        port_value = self.port_field.get_string_value()
        if port_value:
            try:
                port_number = int(port_value)
                if port_number < 1024 or port_number > 0xFFFF:
                    raise ValueError("Port must be between 1024 and 65535.")
            except ValueError as e:
                print(f"Error: {e}")
                return

    def property_change(self, event):
        super.property_change(event)  # equivalent to super.propertyChange(event)
        if event.get_property() == "value":
            self.check_state()
        elif event.get_source() == self.enabled_field:
            if not self.previous_enabled_string:
                self.previous_enabled_string = str(event.get_old_value())
            self.current_enabled_string = str(event.get_new_value())

    def perform_ok(self):
        super.perform_ok()  # equivalent to super.performOk()
        enabled_was_changed = False
        port_was_changed = False
        if self.current_enabled_string and self.previous_enabled_string:
            if self.current_enabled_string != self.previous_enabled_string:
                enabled_was_changed = True

        if self.current_port_string and self.previous_port_string:
            if self.current_port_string != self.previous_port_string:
                port_was_changed = True

        ScriptEditorInitializer.notify_preferences_changed(enabled_was_changed, port_was_changed)
        self.previous_enabled_string = None
        self.previous_port_string = None
        return True

    def perform_cancel(self):
        super.perform_cancel()  # equivalent to super.performCancel()
        self.previous_enabled_string = None
        self.previous_port_string = None
        return True


class BooleanFieldEditor:
    pass  # not implemented in Python, as it is a Java class


class StringFieldEditor:
    pass  # not implemented in Python, as it is a Java class

# Usage example:

page = GhidraScriptEditorPreferencePage()
page.create_field_editors()  # equivalent to createFieldEditors()
