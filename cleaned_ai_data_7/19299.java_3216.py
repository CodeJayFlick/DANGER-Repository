class Option:
    def __init__(self, key: str, default_value):
        self.key = key.lower()
        self.default_value = default_value
        self.parsed_value = default_value

    @property
    def parser(self):
        if isinstance(self.default_value, str):
            return lambda s: s
        else:
            try:
                class_info = Classes.get_exact_class_info(type(self.default_value))
                parser = class_info.get_parser()
                return lambda s: parser.parse(s, ParseContext.CONFIG)
            except Exception as e:
                raise ValueError(f"Invalid default value {self.default_value}")

    def setter(self, setter):
        self.setter = setter
        return self

    def optional(self, is_optional=False):
        self.is_optional = is_optional
        return self

    def set(self, config, path):
        old_value = self.value
        self.value = config.get_by_path(path + self.key)
        if not self.is_optional and self.value is None:
            raise ValueError(f"Required entry '{path}{self.key}' is missing in {config.filename}. Please make sure that you have the latest version of the config.")
        if (old_value != self.value or old_value is None) and self.value is not None:
            parsed_value = self.parser(self.value)
            if parsed_value is None:
                parsed_value = self.default_value
            self.parsed_value = parsed_value
            self.on_value_change()

    def on_value_change(self):
        if hasattr(self, 'setter'):
            self.setter.set(self.parsed_value)

    @property
    def value(self):
        return self.parsed_value

    @property
    def is_optional(self):
        return self.is_optional


class Config:
    pass  # This class needs to be implemented based on your requirements


# Example usage:

config = Config()
option1 = Option('key', 'default')
option2 = option1.setter(lambda x: print(x))
option3 = option1.optional(True)

try:
    config.set(option1, '/path/to/config')
except ValueError as e:
    print(e)
