Here is the translation of the Java code into Python:

```Python
class AttributeManager:
    def __init__(self, attributed_set):
        self.attributed_set = attributed_set
        self_defined_attributes = {}

    INTEGER_TYPE = "INTEGER_ TYPE"
    LONG_TYPE = "LONG_TYPE"
    DOUBLE_TYPE = "DOUBLE_TYPE"
    STRING_TYPE = "STRING_TYPE"
    OBJECT_TYPE = "OBJECT_TYPE"

    def create_attribute(self, attribute_name, attribute_type):
        new_attribute = None
        if attribute_type == self.INTEGER_TYPE:
            new_attribute = IntegerAttribute(self.attributed_set)
        elif attribute_type == self.LONG_TYPE:
            new_attribute = LongAttribute(self.attributed_set)
        elif attribute_type == self.DOUBLE_TYPE:
            new_attribute = DoubleAttribute(self.attributed_set)
        elif attribute_type == self.STRING_TYPE:
            new_attribute = StringAttribute(self.attributed_set)
        elif attribute_type == self.OBJECT_TYPE:
            new_attribute = ObjectAttribute(self.attributed_set)
        else:
            print("Unknown attribute type. New Attribute is null")
        return new_attribute

    def remove_attribute(self, attribute_name):
        if attribute_name in self_defined_attributes:
            del self_defined_attributes[attribute_name]

    def has_attribute_named(self, attribute_name):
        return attribute_name in self_defined_attributes

    def get_attribute(self, attribute_name):
        return self_defined_attributes.get(attribute_name)

    def get_attribute_names(self):
        return list(self_defined_attributes.keys())

    def clear(self):
        for attr in self_defined_attributes.values():
            attr.clear()
```

Please note that Python does not support generics like Java. The `AttributeManager` class is defined to work with any type of attribute, but the actual attributes (like `IntegerAttribute`, etc.) are assumed to be subclasses of a common base class (`KeyedObject`).