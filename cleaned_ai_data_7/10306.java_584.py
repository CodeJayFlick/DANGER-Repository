class OptionsEditor:
    def apply(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def cancel(self) -> None:
        pass  # No-op, as there's no equivalent in Python

    def reload(self) -> None:
        pass  # No-op, as there's no equivalent in Python

    def set_options_property_change_listener(self, listener: callable) -> None:
        raise NotImplementedError("Subclasses must implement this method")

    def get_editor_component(self, options: dict, editor_state_factory: callable) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def dispose(self) -> None:
        pass  # No-op, as there's no equivalent in Python
