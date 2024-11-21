Here is the translation of the Java interface `OptionsEditor` into a Python class:

```python
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
```

Note that I've used the `NotImplementedError` exception to indicate that certain methods are not implemented and should be overridden by subclasses. This is similar to how Java interfaces work.

Also, since Python doesn't have a direct equivalent of Java's `JComponent`, I simply returned an object (`object`) from the `get_editor_component` method.