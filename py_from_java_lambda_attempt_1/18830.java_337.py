Here is the translation of the given Java interface into a Python class:

```Python
class ConfigApi:
    def __init__(self):
        pass

    # Note: When substantial changes in Nessie API (this and related interfaces) are made
    # the API version number reported by NessieConfiguration.get_max_supported_api_version() should be increased as well.

    def get_config(self) -> 'NessieConfiguration':
        """Get the server configuration."""
        pass

class NessieConfiguration:
    @property
    def max_supported_api_version(self):
        return None  # Replace with actual implementation
```

Please note that this is a direct translation of Java code into Python. In Python, we don't have an exact equivalent to interfaces like in Java. Instead, we use abstract classes or protocols (in some frameworks). Here I've used the `ConfigApi` class as it seems you want to encapsulate configuration-related functionality within your API.

The `NessieConfiguration` is a simple class with a property for getting the maximum supported API version. You can replace this placeholder implementation with actual logic based on your requirements.