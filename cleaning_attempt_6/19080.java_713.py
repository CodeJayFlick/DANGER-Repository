class NessieDbAdapter:
    def __init__(self):
        self.config_method = ""

    @property
    def config_method(self):
        return self._config_method

    @config_method.setter
    def config_method(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Config method must be a string")
        self._config_method = value


class DatabaseAdapter:
    pass  # This class is empty in the original Java code as well.


# Example usage:

class MyDatabaseAdapter(DatabaseAdapter):
    @staticmethod
    def apply_test_clock(config: dict) -> dict:
        return config["with_clock"](TEST_CLOCK)

my_adapter = NessieDbAdapter()
my_adapter.config_method = "apply_test_clock"

print(my_adapter.config_method)
