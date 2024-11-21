from abc import ABCMeta, abstractmethod

class AnnotatedSchemaContext:
    def __init__(self):
        pass

    def get_schema_for_class(self, cls):
        raise NotImplementedError("Not implemented")

    def builder(self, name):
        return None  # Not a real method in Java either

def add_basic_attributes(builder: object) -> object:
    builder.add_attribute_schema({"_value": "ANY", "_type": "STRING", "_display": "STRING",
                                   "_short_display": "STRING", "_kind": "STRING", "_order": "INT",
                                   "_modified": "BOOL"}, None)
    return builder

class TestAnnotatedTargetRootPlain(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_plain() -> None:
    pass

class TestAnnotatedTargetRootNoElems(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_no_elems() -> None:
    pass

class TestAnnotatedTargetProcessStub(metaclass=ABCMeta):
    def __init__(self, model: object, parent: object, key: str, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.parent = parent
        self.key = key
        self.type_hint = type_hint

@abstractmethod
def test_annotated_sub_schema_elems_by_param() -> None:
    pass

class TestAnnotatedTargetRootOverriddenFetchElems(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_overriden_fetch_elems() -> None:
    pass

class TestAnnotatedProcessContainer(metaclass=ABCMeta):
    def __init__(self, model: object, parent: object, key: str, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.parent = parent
        self.key = key
        self.type_hint = type_hint

@abstractmethod
def test_annotated_sub_schema_elems_by_param() -> None:
    pass

class TestAnnotatedTargetRootWithAnnotatedAttrs(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_with_annotated_attrs() -> None:
    pass

class TestAnnotatedTargetRootWithListedAttrs(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_with_listed_attrs() -> None:
    pass

class TestAnnotatedTargetRootWithResyncModes(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_with_resyunc_modes() -> None:
    pass

class NotAPrimitive(metaclass=ABCMeta):
    def __init__(self, value: int) -> None:
        super().__init__()
        self.value = value

@abstractmethod
def test_not_annotated() -> None:
    pass

class TestAnnotatedTargetRootWithElemsNonUnique(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_with_elems_non_unique() -> None:
    pass

class TestAnnotatedTargetRootWithAnnotatedAttrsBadType(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_with_annotated_attrs_bad_type() -> None:
    pass

class TestAnnotatedTargetRootWithAnnotatedAttrsBadName(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_with_annotated_attrs_bad_name() -> None:
    pass

class TestAnnotatedTargetRootWithAnnotatedAttrsBadGetter(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_with_annotated_attrs_bad_getter() -> None:
    pass

class TestAnnotatedTargetRootWithListedAttrsBadType(metaclass=ABCMeta):
    def __init__(self, model: object, type_hint: str) -> None:
        super().__init__()
        self.model = model
        self.type_hint = type_hint

@abstractmethod
def test_annotated_root_schema_with_list_attrs_bad_type() -> None:
    pass
