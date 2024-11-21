Here is the equivalent Python code:

```
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
```

Note that Python does not have a direct equivalent of Java's annotations. The `@` symbol in front of functions or classes is used for decorators, which are a different concept. In this translation, I've simply defined the same class and attributes as in the original code, without using any annotation-like syntax.

Also note that Python has no built-in support for enums like Java does. Instead, we can use the `enum` module to define an enum class.