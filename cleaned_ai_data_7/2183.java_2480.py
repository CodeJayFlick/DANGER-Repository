from abc import ABC, abstractmethod
import asyncio

class TargetConfigurable(ABC):
    BASE_ATTRIBUTE_NAME = "base"

    async def write_configuration_option(self, key: str, value) -> asyncio.Future:
        # This method should probably be replaced with a configure(options) method.
        pass  # TODO: Implement this properly in all subclasses to advertise their parameters.

    @abstractmethod
    async def get_configurable_options(self) -> dict:
        return {}
