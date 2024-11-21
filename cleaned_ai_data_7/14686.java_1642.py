# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

from typing import TypeVar, Generic

I = TypeVar('I')
O = TypeVar('O')

class Handler(Generic[I, O]):
    def process(self, input: I) -> O:
        pass
