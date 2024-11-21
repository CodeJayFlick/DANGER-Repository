Here is a translation of the Java code into equivalent Python:

```Python
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
```

This Python code does not exactly replicate the Java code, but it captures its essence. It defines a class `StoreType` with an abstract method `value`, and then provides a concrete implementation of this interface in the form of a subclass called `Literal`. The `STORE_TYPES` dictionary is used to store instances of these literal values for easy lookup by name.

The Python code does not have direct equivalents for Java's annotations (`@Target`, `@Retention`, etc.), so I've omitted those.