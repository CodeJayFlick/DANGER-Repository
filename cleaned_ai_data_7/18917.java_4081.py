# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

from abc import ABCMeta, abstractmethod

class StoreType(metaclass=ABCMeta):
    @abstractmethod
    def value(self) -> str:
        pass

class Literal(StoreType):
    def __init__(self, value: str):
        self.value = value

    def value(self) -> str:
        return self.value

# Define the possible store types as a dictionary for easy lookup.
STORE_TYPES = {
    'value': Literal('value'),
}

def get_store_type(store_type_name: str) -> StoreType:
    if store_type_name in STORE_TYPES:
        return STORE_TYPES[store_type_name]
    else:
        raise ValueError(f"Invalid store type '{store_type_name}'")
