# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

class DebugHostScriptHost:
    def __init__(self):
        pass

    def create_context(self, script: 'DataModelScript') -> 'DebugHostContext':
        # Implement your logic here
        pass


from abc import ABC, abstractmethod

class UnknownEx(ABC):
    @abstractmethod
    def unknown_method(self) -> None:
        pass


class DataModelScript:
    pass


class DebugHostContext:
    pass
