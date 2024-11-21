from abc import ABCMeta, abstractmethod
import collections as col

class AnnotatedSaveable(metaclass=ABCMeta):
    accessor_factories = None
    
    @abstractmethod
    def save(self, obj_storage: 'ObjectStorage') -> None:
        pass

    @abstractmethod
    def restore(self, obj_storage: 'ObjectStorage') -> None:
        pass

    class SaveableField:
        pass

class FieldAccessor(metaclass=ABCMeta):
    @abstractmethod
    def save(self, annotated_saveable: AnnotatedSaveable, obj_storage: 'ObjectStorage') -> None:
        pass

    @abstractmethod
    def restore(self, annotated_saveable: AnnotatedSaveable, obj_storage: 'ObjectStorage') -> None:
        pass

class AbstractFieldAccessor(metaclass=ABCMeta):
    def __init__(self, field: 'Field', obj_getter: callable, obj_putter: callable) -> None:
        self.field = field
        self.obj_getter = obj_getter
        self.obj_putter = obj_putter

    @abstractmethod
    def save(self, annotated_saveable: AnnotatedSaveable, obj_storage: 'ObjectStorage') -> None:
        pass

    @abstractmethod
    def restore(self, annotated_saveable: AnnotatedSaveable, obj_storage: 'ObjectStorage') -> None:
        pass

class BoolFieldAccessor(AbstractFieldAccessor):
    def __init__(self, field: 'Field') -> None:
        super().__init__(field, ObjectStorage.get_boolean, ObjectStorage.put_boolean)

class ByteFieldAccessor(AbstractFieldAccessor):
    def __init__(self, field: 'Field') -> None:
        super().__init__(field, ObjectStorage.get_byte, ObjectStorage.put_byte)

# ... and so on for each type of FieldAccessor

AnnotatedSaveable.accessor_factories = ImmutableMap.builder() \
    .put(bool.__class__, BoolFieldAccessor) \
    .put(Boolean.__class__, BoolFieldAccessor) \
    .put(byte.__class__, ByteFieldAccessor) \
    # ... and so on for each type of accessor factory
    .build()

class AnnotatedSaveableException(Exception):
    pass

class ObjectStorage:
    @staticmethod
    def get_boolean(obj_storage: 'ObjectStorage') -> bool:
        raise NotImplementedError('Method not implemented')

    @staticmethod
    def put_boolean(obj_storage: 'ObjectStorage', value: bool) -> None:
        raise NotImplementedError('Method not implemented')

# ... and so on for each type of getter/putter method

class AnnotatedSaveable:
    def __init__(self):
        self.fields = []
        self.field_classes = []

        cls = self.__class__
        while True:
            if cls == object:  # base class
                break
            collect_annotated_fields(self.fields, cls)
            cls = cls.__base__

        for i in range(len(self.fields)):
            factory = AnnotatedSaveable.accessor_factories.get(type(self.fields[i]).__class__)
            self.fields[i] = factory.apply(self.fields[i])
            self.field_classes.append(type(self.fields[i]))

    @staticmethod
    def collect_annotated_fields(fields: list, cls):
        if cls == object:
            return

        for f in cls.__dict__.values():
            if isinstance(f, property) and hasattr(f, 'fget') and hasattr(f.fget, '__name__'):
                annot = getattr(f.fget, 'SaveableField')
                fields.append(f)
        collect_annotated_fields(fields, type(cls).__base__)

    def save(self, obj_storage: 'ObjectStorage') -> None:
        for fa in self.fields:
            fa.save(self, obj_storage)

    def restore(self, obj_storage: 'ObjectStorage') -> None:
        for fa in self.fields:
            fa.restore(self, obj_storage)
