Here is the translation of the Java code to Python:

```Python
class SimpleThreat:
    def __init__(self, threat_type: 'ThreatType', id: int, name: str):
        self.threat_type = threat_type
        self.id = id
        self.name = name

    @property
    def name(self) -> str:
        return self.name

    @property
    def id(self) -> int:
        return self.id

    @property
    def type(self) -> 'ThreatType':
        return self.threat_type


class ThreatType:
    pass  # You need to define this class further based on your requirements.
```

Note that Python does not have direct equivalents for Java's `@ToString`, `@EqualsAndHashCode` and `@RequiredArgsConstructor`. These are Lombok annotations, which generate boilerplate code. In the above translation, I've used Python's property decorator (`@property`) to achieve similar functionality.

Also note that in Python, you don't need to explicitly define getter methods for properties like Java does with getters and setters. The `@property` decorator automatically generates a getter method when accessed as an attribute (e.g., `simple_threat.name`).