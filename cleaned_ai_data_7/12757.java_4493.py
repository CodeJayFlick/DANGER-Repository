# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

from abc import ABC, abstractmethod


class DiscoverableAddressCorrelator(ABC):
    @abstractmethod
    def __init__(self):
        pass  # This interface has no methods.

    def get_extension_point(self) -> str:
        return "Discoverable Address Correlators"
