Here is a translation of the Java code into equivalent Python:

```Python
class Event:
    def __init__(self, content):
        self.content = content
        self.has_been_handled = False

    @classmethod
    def simple(cls) -> 'Event[None]':
        return cls(None)

    def has_been_handled(self) -> bool:
        return self.has_been_handled

    def get_content_or_throw(self) -> any:
        if not self.has_been_handled:
            self.has_been_handled = True
            return self.content
        else:
            raise Exception("Event already handled")

    def get_content_if_not_handled(self) -> any:
        if self.has_been_handled:
            return None
        self.has_been_handled = True
        return self.content

class Observer(metaclass=abc.ABCMeta):
    @abstractmethod
    def on_event(self, content: any) -> None:
        pass

    def __call__(self, event: 'Event[any]') -> None:
        if not event.has_been_handled():
            try:
                self.on_event(event.get_content_or_throw())
            except Exception as e:
                print(f"Error in on_event callback: {e}")
```

Please note that Python does not have direct equivalent of Java's `checkState` method. Instead, we are raising an exception if the event has already been handled when calling `get_content_or_throw`.