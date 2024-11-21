Here is the translation of the given Java code into equivalent Python:

```Python
import random
from typing import List, Dict

class Service:
    def __init__(self, db: object, *exceptions):
        self.database = db
        self.exceptions_list = [exception for exception in exceptions]

    @abstractmethod
    def receive_request(self, *parameters) -> str:
        pass

    @abstractmethod
    def update_db(self, *parameters) -> str:
        pass

    def generate_id(self) -> str:
        random_string = ''
        while len(random_string) < 12:  # length of the random string.
            index = int(random.random() * len('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'))
            random_string += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'[index]
        id = random_string
        if USED_IDS.get(id):
            while USED_IDS[id]:
                id = self.generate_id()
        return id

class DatabaseUnavailableException(Exception):
    pass


# Usage example:
db = object()  # Replace with your actual database instance.
service = Service(db, Exception('Some exception'))
print(service.receive_request())  # This will call the abstract method
```

Please note that Python does not have direct equivalent of Java's `ArrayList`, `Hashtable` and other classes. You can use built-in list and dictionary for similar functionality.

Also, in this translation, I used `@abstractmethod` decorator to define abstract methods which are required by subclasses.