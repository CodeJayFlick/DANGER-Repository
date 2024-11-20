# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

class InstructionTableObserver:
    def __init__(self):
        pass

    def changed(self):
        # method to be implemented by subclasses
        pass


from abc import ABC, abstractmethod

class Observer(ABC):
    @abstractmethod
    def update(self):
        pass
