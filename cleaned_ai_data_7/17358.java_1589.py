class StartTriggerPlan:
    def __init__(self):
        self.trigger_name = None
        super().__init__(False, "START_TRIGGER")

    def set_trigger_name(self, trigger_name: str) -> None:
        self.trigger_name = trigger_name

    @property
    def get_trigger_name(self) -> str:
        return self.trigger_name


class PhysicalPlan:
    def __init__(self):
        pass

    def serialize_to_stream(self, stream):
        raise NotImplementedError("This method must be implemented by the subclass")

    def deserialize_from_buffer(self, buffer: bytes) -> None:
        raise NotImplementedError("This method must be implemented by the subclass")


class StartTriggerPhysicalPlan(StartTriggerPlan, PhysicalPlan):
    @property
    def get_paths(self) -> list[PartialPath]:
        return []

    def serialize_to_stream(self, stream) -> None:
        stream.write(int.to_bytes(ord("START_TRIGGER"), 1, "big"))
        self.serialize_string(stream, self.trigger_name)

    def deserialize_from_buffer(self, buffer: bytes) -> None:
        trigger_name = self.deserialize_string(buffer)
        self.set_trigger_name(trigger_name)


class PartialPath:
    pass


def put_string(stream, string):
    stream.write(string.encode())


def read_string(buffer):
    return buffer.read().decode()


if __name__ == "__main__":
    start_trigger_plan = StartTriggerPhysicalPlan()
    start_trigger_plan.set_trigger_name("my_trigger")
