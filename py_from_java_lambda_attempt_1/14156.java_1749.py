Here is the translation of the given Java code into Python:

```Python
class DomainEvent:
    def __init__(self, sequence_id: int, created_time: int, event_class_name: str):
        self.sequence_id = sequence_id
        self.created_time = created_time
        self.event_class_name = event_class_name

    @property
    def real_time(self) -> bool:
        return True  # Default value for 'realTime' in Java is true.

    def process(self):
        pass  # Abstract method, no implementation provided.
```

Note that Python does not have direct equivalents to Java's `@Setter`, `@Getter` and `@RequiredArgsConstructor`. The equivalent functionality can be achieved using Python properties.