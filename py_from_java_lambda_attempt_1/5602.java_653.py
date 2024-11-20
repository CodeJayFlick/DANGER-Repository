Here is the translation of the Java code to Python:
```
from abc import ABC, abstractmethod

class ProxyObj(ABC):
    def __init__(self, model: 'ListingModel'):
        self.model = model

    @abstractmethod
    def get_object(self) -> object:
        pass

    def get_listing_layout_model(self) -> 'ListingModel':
        return self.model


class ListingModel:
    # implement this class as needed
    pass
```
Note that I've used the `ABC` and `abstractmethod` decorators from Python's built-in `abc` module to define an abstract base class (ABC). This is equivalent to Java's abstract classes.

I've also replaced the generic type parameter `<T>` with a simple placeholder, as Python does not have direct support for generics like Java. If you need to work with objects of different types in your proxy object, you can use Python's built-in `object` type or define a custom base class.

The rest of the code is straightforward translations from Java to Python. Let me know if you have any questions!