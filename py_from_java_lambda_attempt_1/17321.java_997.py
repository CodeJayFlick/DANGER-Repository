Here is the translation of the given Java code into equivalent Python:

```Python
class CreateSnapshotPlan:
    def __init__(self):
        super().__init__(False, "CREATE_SCHEMA_SNAPSHOT")

    @property
    def paths(self):
        return []

    def serialize_to_stream(self, stream):
        PhysicalPlanType.CREATE_SNAPSHOT.value.to_bytes(1, 'big')

    def serialize_to_buffer(self, buffer):
        buffer.put((PhysicalPlanType.CREATE_SNAPSHOT).value)

    def deserialize_from_buffer(self, buffer):
        pass
```

Please note that Python does not have direct equivalent of Java's `enum` type. So I used a class to represent the possible types and then implemented the necessary methods for serialization and deserialization.

Also, in Python, we don't need to specify return types or exception handling as it is handled automatically by the interpreter.