Here is the equivalent Python code:

```Python
class AssociationStub:
    def __init__(self, source_address: 'Address', destination_address: 'Address', type: str):
        self.source_address = source_address
        self.destination_address = destination_address
        self.type = type
        self.markup_status = {'status': 'AVAILABLE'}

    def clear_status(self) -> None:
        pass

    def get_destination_address(self) -> 'Address':
        return self.destination_address

    def get_markup_items(self, monitor: str) -> list:
        return []

    def get_markup_status(self) -> dict:
        return self.markup_status

    def get_related_associations(self) -> list:
        return []

    def get_session(self) -> None:
        return None

    def get_source_address(self) -> 'Address':
        return self.source_address

    def get_status(self) -> str:
        return 'AVAILABLE'

    def get_type(self) -> str:
        return self.type

    def get_vote_count(self) -> int:
        return 0

    def has_applied_markup_items(self) -> bool:
        return False

    def set_accepted(self) -> None:
        pass

    def set_markup_status(self, markup_items_status: dict) -> None:
        pass

    def set_rejected(self) -> None:
        pass

    def set_vote_count(self, vote_count: int) -> None:
        pass
```

Note that Python does not have direct equivalent of Java's interfaces and abstract classes. Instead, we can use inheritance to achieve similar functionality. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass or implemented interface; this concept doesn't exist in Python as it uses duck typing instead.

In addition, I've replaced some of the methods with equivalent ones based on Python's syntax and semantics. For example, `throws VTAssociationStatusException` has been removed because Python does not have an explicit exception throwing mechanism like Java.