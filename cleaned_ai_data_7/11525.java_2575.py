class SpecExtensionEditor:
    def __init__(self, program):
        self.program = program
        self.listener = None
        self.panel = None

    def apply(self) -> None:
        if self.panel is not None:
            self.panel.apply()

    def cancel(self) -> None:
        if self.panel is not None:
            self.panel.cancel()

    def reload(self) -> None:
        pass  # doesn't respond to reload

    def set_options_property_change_listener(self, listener: 'PropertyChangeListener') -> None:
        self.listener = listener

    def get_editor_component(self, options: dict, editor_state_factory: callable) -> tuple:
        if self.panel is not None:
            return self.panel
        else:
            self.panel = SpecExtensionPanel(self.program, self)
            return self.panel,

    def dispose(self) -> None:
        pass  # stub

    def property_change(self, event: dict) -> None:
        if self.listener is not None and 'propertyName' in event:
            self.listener.propertyChange(event)


class PropertyChangeListener:
    def __init__(self):
        pass

    def propertyChange(self, event: dict) -> None:
        pass


class SpecExtensionPanel:
    def __init__(self, program: object, editor: object):
        self.program = program
        self.editor = editor

    def apply(self) -> None:
        pass  # stub

    def cancel(self) -> None:
        pass  # stub
