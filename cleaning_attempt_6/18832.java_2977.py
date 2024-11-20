from typing import Dict, Any

class HttpConfigApi:
    def __init__(self):
        pass

    @property
    def config(self) -> Dict[str, Any]:
        return self._config

    @config.setter
    def config(self, value: NessieConfiguration) -> None:
        self._config = value


def get_config() -> NessieConfiguration:
    # implement the logic to retrieve configuration settings here
    pass
