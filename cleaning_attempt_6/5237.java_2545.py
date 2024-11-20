class StructConverterUtil:
    def __init__(self):
        pass

    @staticmethod
    def to_data_type(object=None) -> dict:
        if object is None or not isinstance(object, type):
            return {"name": "Unknown", "fields": []}
        name = self.parse_name(object.__name__)
        struct = {"name": name, "fields": []}
        fields = self.get_fields(object)
        for field in fields:
            if self.is_valid_field(field):
                dt = self.get_data_type(field, object())
                struct["fields"].append({"name": field.name, "type": str(dt)})
        return struct

    @staticmethod
    def get_fields(clazz) -> list:
        fields = []
        if clazz is not None and hasattr(clazz, "__bases__"):
            for super_field in self.get_fields(type.__dict__[clazz.__base__.__name__]):
                fields.append(super_field)
        for field_name in dir(clazz):
            field = getattr(clazz, field_name)
            if isinstance(field, property) or callable(getattr(field, "fget", None)):
                continue
            try:
                if not hasattr(field, "__code__"):
                    fields.append(field)
            except AttributeError:
                pass
        return fields

    @staticmethod
    def is_valid_field(field):
        modifiers = field.__dict__.get("__defaults__")[0]
        if Modifier.is_static(modifiers) or (not Modifier.is_private(modifiers) and not Modifier.is_protected(modifiers)):
            return False
        name = str(field.name)
        if name.startswith("_"):
            return False
        return True

    @staticmethod
    def get_data_type(field, object=None):
        field_class = type.__dict__[field.__name__].__annotations__.get("return")
        if isinstance(field_class, list) and len(field_class) > 0:
            array_field_class = field_class[0]
            return {"type": str(array_field_class), "length": len(getattr(object, field.name))}
        elif issubclass(field_class, (int, float)):
            return {"type": str(type.__dict__[str(field_class)])}
        else:
            raise Exception(f"Unsupported data type for automatic structure conversion - {field_class}")

    @staticmethod
    def parse_name(name):
        pos = name.rfind('.')
        if pos == -1:  # in a default package
            return name
        return name[pos + 1:]

# Test the code
print(StructConverterUtil.to_data_type())
