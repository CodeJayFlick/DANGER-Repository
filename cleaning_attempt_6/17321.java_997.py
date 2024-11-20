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
