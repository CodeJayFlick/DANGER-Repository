Here is the equivalent Python code:

```Python
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
```

Please note that Python does not have direct equivalent of Java's annotations. However, we can achieve similar functionality using Python's property and setter methods to control the behavior of an attribute.

In this example, `NessieDbAdapter` class has a `config_method` attribute which is controlled by its getter and setter methods. The `@property` decorator makes it possible to access the attribute like a property in Java.