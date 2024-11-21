Here is the equivalent Python code:

```Python
class OptionUtils:
    @staticmethod
    def contains_option(option_name: str, options: list) -> bool:
        return any(o.name == option_name for o in options)

    @staticmethod
    def get_option(option_name: str, options: list, default_value=None) -> object:
        if options is not None:
            for option in options:
                if option.name == option_name:
                    return option.value
        return default_value

    @staticmethod
    def get_boolean_option_value(option_name: str, options: list, default_value=False) -> bool:
        if options is not None:
            for option in options:
                if option.name == option_name:
                    value = option.value
                    if isinstance(value, bool):
                        return value
        return default_value

```

Please note that Python does not have a direct equivalent to Java's Option class. In this translation, I assumed the `Option` class has attributes like `name`, and `value`.