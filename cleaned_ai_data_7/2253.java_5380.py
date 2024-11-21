class TestTargetNamedDataType:
    def __init__(self, parent, name: str, kind: 'NamedDataTypeKind', type_hint: str):
        super().__init__(parent, PathUtils.make_key(name), type_hint)

        self.change_attributes([], {'NAMED_DATA_TYPE_KIND_ATTRIBUTE_NAME': kind}, "Initialized")

class DefaultTestTargetObject:
    def __init__(self, parent, key, type_hint):
        pass

class TestTargetDataTypeNamespace:
    pass

class NamedDataTypeKind:
    pass
