class QuarkusNessieAuthorizationConfig:
    def __init__(self):
        self.enabled = False  # default value for 'enabled'
        self.rules = {}  # default value for 'rules'

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        if not isinstance(value, bool):
            raise ValueError("Enabled must be a boolean")
        self._enabled = value

    @property
    def rules(self):
        return self._rules

    @rules.setter
    def rules(self, value: dict):
        if not isinstance(value, dict):
            raise ValueError("Rules must be a dictionary")
        self._rules = value


# Example usage:
config = QuarkusNessieAuthorizationConfig()
print(config.enabled)  # prints False
print(config.rules)  # prints {}
