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
