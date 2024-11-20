Here is the translation of the Java code to Python:
```
# Copyright 2020 Dremio

import abc

class NessieConfiguration(abc.ABC):
    def __init__(self):
        pass

    @property
    def default_branch(self) -> str:
        raise NotImplementedError("default_branch must be implemented")

    @property
    def max_supported_api_version(self) -> int:
        raise NotImplementedError("max_supported_api_version must be implemented")


class ImmutableNessieConfiguration(NessieConfiguration):
    def __init__(self, default_branch: str, max_supported_api_version: int):
        super().__init__()
        self._default_branch = default_branch
        self._max_supported_api_version = max_supported_api_version

    @property
    def default_branch(self) -> str:
        return self._default_branch

    @property
    def max_supported_api_version(self) -> int:
        return self._max_supported_api_version


class ConfigApiImpl:
    def __init__(self, config: dict):
        self.config = config

    def get_config(self) -> ImmutableNessieConfiguration:
        default_branch = self.config["defaultBranch"]
        max_supported_api_version = 1
        return ImmutableNessieConfiguration(default_branch, max_supported_api_version)
```
Note that I had to make some assumptions about the Python code structure and naming conventions. Specifically:

* I used `abc` (Abstract Base Classes) for the abstract base class `NessieConfiguration`.
* I defined a concrete implementation of `NessieConfiguration`, `ImmutableNessieConfiguration`, with properties for `default_branch` and `max_supported_api_version`.
* I created a new Python class, `ConfigApiImpl`, which has an initializer that takes a dictionary as input. The `get_config()` method returns an instance of `ImmutableNessieConfiguration`.

Please let me know if this translation meets your requirements or if you need further modifications!