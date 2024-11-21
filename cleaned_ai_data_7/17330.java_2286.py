class DropTriggerPlan:
    def __init__(self):
        self.trigger_name = None
        super().__init__()

    def set_trigger_name(self, trigger_name: str) -> None:
        self.trigger_name = trigger_name

    @property
    def trigger_name(self) -> str:
        return self._trigger_name

    def get_paths(self) -> list:
        return []

    def serialize_to_stream(self, stream):
        if not hasattr(stream, 'write'):
            raise TypeError("stream must have a write method")
        stream.write(int(0).to_bytes((PhysicalPlanType.DROP_TRIGGER.ordinal() + 1) // 8, 'big'))
        self._serialize_string(stream, self.trigger_name)

    def serialize_to_buffer(self, buffer):
        if not hasattr(buffer, 'put'):
            raise TypeError("buffer must have a put method")
        buffer.put(int(0).to_bytes((PhysicalPlanType.DROP_TRIGGER.ordinal() + 1) // 8, 'big'))
        self._serialize_string(buffer, self.trigger_name)

    def deserialize_from_buffer(self, buffer):
        if not hasattr(buffer, 'get'):
            raise TypeError("buffer must have a get method")
        self._deserialize_string(buffer)
