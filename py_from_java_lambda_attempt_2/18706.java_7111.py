Here is the equivalent Python code:

```Python
from datetime import date

class Pet:
    def __init__(self):
        self.id = None
        self.breed = None
        self.name = None
        self.date_of_birth = None

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def breed(self):
        return self._breed

    @breed.setter
    def breed(self, value):
        self._breed = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def date_of_birth(self):
        return self._date_of_birth

    @date_of_birth.setter
    def date_of_birth(self, value):
        if isinstance(value, str):
            try:
                self._date_of_birth = date.fromisoformat(value)
            except ValueError as e:
                raise ValueError("Invalid date format. Please use YYYY-MM-DD.") from e
        else:
            self._date_of_birth = value

# Example usage:

pet1 = Pet()
pet1.id = "123"
pet1.breed = "Golden Retriever"
pet1.name = "Max"
pet1.date_of_birth = "2020-01-01"

print(pet1.id)  # prints: 123
print(pet1.breed)  # prints: Golden Retriever
print(pet1.name)  # prints: Max
print(pet1.date_of_birth)  # prints: 2020-01-01

pet2 = Pet()
pet2.id = "456"
pet2.breed = "Poodle"
pet2.name = "Luna"
pet2.date_of_birth = date(2015, 6, 15)

print(pet2.id)  # prints: 456
print(pet2.breed)  # prints: Poodle
print(pet2.name)  # prints: Luna
print(pet2.date_of_birth)  # prints: 2015-06-15
```