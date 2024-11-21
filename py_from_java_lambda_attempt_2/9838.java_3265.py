Here is the translation of the Java interface `SelectionStorage` to a Python class:

```python
from typing import List, Any

class SelectionStorage:
    def get_last_selected_objects(self) -> List[Any]:
        pass  # Implement this method in your subclass

    def set_last_selected_objects(self, last_selected_objects: List[Any]) -> None:
        pass  # Implement this method in your subclass
```

Note that I used the `Any` type to represent the generic type parameter `<T>` from Java. In Python, we don't have a direct equivalent of generics like Java does, but using `Any` allows us to indicate that the class can work with objects of any type.

Also, in Python, interfaces are not directly supported as they are in Java. Instead, I defined an abstract base class (`SelectionStorage`) that provides placeholders for the two methods from the original interface. Any subclass of this class will need to implement these methods.