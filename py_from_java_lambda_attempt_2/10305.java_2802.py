Here's the translation of the given Java interface into a Python class:

```Python
class OptionsChangeListener:
    def options_changed(self, options: dict, option_name: str, old_value: object, new_value: object) -> None:
        pass  # This method should be overridden by subclasses to handle changes in options.
```

In this translation, the Java interface `OptionsChangeListener` is converted into a Python class with one method `options_changed`. The method takes four parameters - `options`, `option_name`, `old_value`, and `new_value` - which are equivalent to their counterparts in the original Java code.