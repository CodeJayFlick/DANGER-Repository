class JdiModelTargetAttributesContainer:
    def __init__(self, parent: 'JdiModelTargetObject', name):
        super().__init__(parent, name)

    def add_attributes(self, attrs: dict) -> None:
        self.set_attributes([], attrs, "Initialized")

# Note that Python does not have direct equivalent of Java's @annotation
class TargetObjectSchemaInfo:
    pass

@classmethod
def target_object_schema_info(cls):
    return cls()

TargetObjectSchemaInfo.target_object_schema_info = classmethod(target_object_schema_info)

