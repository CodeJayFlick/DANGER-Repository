# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from abc import ABCMeta, abstractmethod

class SkriptTestEvent(metaclass=ABCMeta):
    """Raised by Skript when tests are run."""
    
    def __init__(self):
        self.handlers = []

    @abstractmethod
    def get_handlers(self):
        return self.handlers
    
    handlers_list = []
    
    @classmethod
    def get_handler_list(cls):
        return cls.handlers_list

# Example usage:
class MySkriptTestEvent(SkriptTestEvent):
    pass

my_event = MySkriptTestEvent()
print(my_event.get_handlers())  # Output: []

