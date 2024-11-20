Here is the translation of the given Java code into equivalent Python:

```Python
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

from abc import ABC, abstractmethod


class GadpClientTargetTogglable(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def get_target(self) -> None:
        pass

    @abstractmethod
    def set_target(self, target: None) -> None:
        pass

# Nothing to add