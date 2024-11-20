Here is the equivalent Python code for the given Java file:

```Python
import uuid
from datetime import date

class Pet:
    def __init__(self, id=None, breed=None, name=None, dob=None):
        self.id = id
        self.breed = breed
        self.name = name
        self.dob = dob


class PetsController:
    model = None
    list = []
    id = None

    def show(self):
        return {"show": "success"}

    def index(self):
        names = PetData.get_names()
        pets = [Pet(uuid.uuid4().hex, uuid.uuid4().hex, name, date.today()) for name in names]
        self.list = pets
        return {"index": "success"}


    def create(self):
        if not (self.model.name and self.model.breed):
            return None

        db_pet = Pet(**self.model.__dict__)
        db_pet.id = uuid.uuid4().hex
        return {"success": True, "location_id": db_pet.id}

    def update(self):
        # TODO: UPDATE LOGIC
        return "success"

    def destroy(self):
        # TODO: DELETE LOGIC
        return "success"


    @property
    def id(self):
        if self._id:
            self.model = Pet(id=self._id, breed=PetData.get_random_breed(), name=PetData.get_random_name(), dob=PetData.get_random_dob())
        return self._id

    @id.setter
    def id(self, value):
        self._id = value


class ModelDriven:
    pass


# This is not a standard Python class. It seems like it's used to implement the interface in Java.
```

Please note that this code does not include any database operations or actual REST API functionality as it was translated from Java and might require adjustments for your specific use case.

Also, I didn't translate all of the Java code into equivalent Python because some parts are missing (like PetData class) and also there is no direct translation for certain constructs like `DefaultHttpHeaders` in Java.