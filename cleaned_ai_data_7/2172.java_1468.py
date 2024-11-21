import enum

class TargetObjectSchemaInfo:
    def __init__(self):
        self.name = ""
        self.canonical_container = False
        self.elements = []
        self.element_resync = ResyncMode.NEVER.value
        self.attributes = []
        self.attribute_resync = ResyncMode.NEVER.value


class ResyncMode(enum.Enum):
    NEVER = 0
    ALWAYS = 1

TargetObjectSchemaInfo.name.default = ""
TargetObjectSchemaInfo.canonical_container.default = False
TargetObjectSchemaInfo.elements.default = []
TargetObjectSchemaInfo.element_resync.default = ResyncMode.NEVER.value
TargetObjectSchemaInfo.attributes.default = []
TargetObjectSchemaInfo.attribute_resync.default = ResyncMode.NEVER.value

class TargetElementType:
    pass


# This is equivalent to the Java annotation @Retention(RetentionPolicy.RUNTIME)
def target_object_schema_info(cls):
    return cls
