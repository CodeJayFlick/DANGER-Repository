class FactoryStructureDataType:
    def __init__(self, name):
        self.name = name

    def clone(self) -> 'FactoryStructureDataType':
        return self.__class__()

    @property
    def length(self):
        return -1

    def get_value(self, buf: bytes, settings=None, length=-1) -> object:
        return None

    def get_representation(self, buf: bytes, settings=None, length=-1) -> str:
        return None

    @property
    def description(self):
        return "Dynamic Data Type should not be instantiated directly"

    def get_data_type(self, buf: bytes) -> 'Structure':
        struct = StructureDataType(self.name)
        if buf is not None:
            self.populate_dynamic_structure(buf, struct)
            struct = self.set_category_path(struct, buf)
        return struct

    def set_category_path(self, struct: 'Structure', buf: bytes) -> 'Structure':
        path = CategoryPath.ROOT
        try:
            path = CategoryPath(CategoryPath.ROOT, f"{buf.hex()}")
        except Exception as e:
            pass
        self.set_category(struct, path)
        return struct

    def set_category(self, dt: object, path: str):
        if not isinstance(dt, (Structure, Union, TypeDef)):
            raise TypeError("Invalid data type")
        try:
            dt.category_path = path
        except Exception as e:
            pass
        if isinstance(dt, Structure):
            for comp in dt.components:
                self.set_category(comp.data_type, path)
        elif isinstance(dt, Union):
            for comp in dt.components:
                self.set_category(comp.data_type, path)

    def add_component(self, es: 'Structure', dt: object, component_name) -> 'DataTypeComponent':
        return es.add(dt, dt.length, component_name, None)

    def populate_dynamic_structure(self, buf: bytes, es: 'Structure'):
        pass

class Structure:
    def __init__(self):
        self.components = []

    def add(self, dt: object, length, name, parent=None) -> 'DataTypeComponent':
        return DataTypeComponent(dt, length, name, parent)

class CategoryPath:
    ROOT = "ROOT"

    def __init__(self, path, address):
        self.path = path
        self.address = address

    @property
    def category_path(self):
        return f"{self.path}/{self.address}"

class StructureDataType(FactoryStructureDataType):
    pass

class Union(DataTypeComponent):
    def __init__(self):
        super().__init__()
        self.components = []

    def add_component(self, dt: object) -> 'DataTypeComponent':
        component = DataTypeComponent(dt)
        self.components.append(component)
        return component
