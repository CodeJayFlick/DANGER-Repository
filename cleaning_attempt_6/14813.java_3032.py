class Person:
    def __init__(self, name: str, surname: str, age: int):
        self.name = name
        self.surname = surname
        self.age = age

    @property
    def id(self) -> int:
        return 0  # Assuming the ID is not needed in Python

    @id.setter
    def id(self, value: int):
        pass  # No setter for ID as it's assumed to be generated automatically

from dataclasses import dataclass, field

@dataclass(frozen=True)
class Person:
    name: str
    surname: str
    age: int
