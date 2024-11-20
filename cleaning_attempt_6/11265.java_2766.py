class PluginException(Exception):
    def __init__(self, message, details=None):
        if details:
            super().__init__("Can't add plugin: " + str(message) + ". " + str(details))
        else:
            super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)

    @classmethod
    def from_message_and_cause(cls, message, cause):
        return cls(message, cause)

    def get_plugin_exception(self, e=None):
        if not e:
            return self
        return PluginException(f"{e.message}\n{self.message}")
