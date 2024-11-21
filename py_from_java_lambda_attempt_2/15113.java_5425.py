Here is the translation of the Java interface `HotelDao` to a Python class:

```python
from typing import Optional, Stream

class HotelDAO:
    def get_all(self) -> list:
        # Implement your logic here to return all rooms as a list
        pass

    def get_by_id(self, room_id: int) -> Optional[dict]:
        # Implement your logic here to return the room with the given id or None if not found
        pass

    def add_room(self, room: dict) -> bool:
        # Implement your logic here to add a new room and return True on success, False otherwise
        pass

    def update_room(self, room: dict) -> bool:
        # Implement your logic here to update an existing room and return True on success, False otherwise
        pass

    def delete_room(self, room: dict) -> bool:
        # Implement your logic here to delete a room and return True on success, False otherwise
        pass
```

Note that Python does not have built-in support for interfaces like Java. Instead, we define an abstract class `HotelDAO` with methods that need to be implemented by any concrete subclass.

Also, the concept of `Stream<Room>` in Java is equivalent to a generator or iterator in Python, which can be used to process large datasets efficiently. However, since this code snippet does not provide specific implementation details for these methods, I have left them as abstract placeholders (`pass`) that need to be implemented by any concrete subclass.

Finally, the `Optional<Room>` type in Java is equivalent to a nullable dictionary or None value in Python.