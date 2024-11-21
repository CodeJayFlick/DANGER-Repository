Here is the translation of the Java code into Python:

```Python
class BlockModelService:
    def __init__(self):
        self.models = {}
        self.listeners = []

    BASIC_MODEL = 1
    SUBROUTINE_MODEL = 2

    SIMPLE_BLOCK_MODEL_NAME = "SimpleBlockModel"
    MULTI_ENTRY_SUBROUTINE_MODEL_NAME = "MultEntSubModel"
    ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME = "IsolatedEntrySubModel"
    OVERLAPPED_SUBROUTINE_MODEL_NAME = "OverlapCodeSubModel"
    PARTITIONED_SUBROUTINE_MODEL_NAME = "PartitionCodeSubModel"

    DEFAULT_BLOCK_MODEL_NAME = SIMPLE_BLOCK_MODEL_NAME
    DEFAULT_SUBROUTINE_MODEL_NAME = MULTI_ENTRY_SUBROUTINE_MODEL_NAME

    def register_model(self, model_class: type, name: str):
        self.models[name] = model_class

    def unregister_model(self, model_class: type):
        for key in list(self.models.keys()):
            if self.models[key] == model_class:
                del self.models[key]
                break

    @property
    def active_block_model_name(self) -> str:
        return next((name for name in self.models), None)

    @property
    def active_subroutine_model_name(self) -> str:
        return next((name for name, _model_class in self.models.items() if issubclass(_model_class, CodeBlockModel)), None)

    def get_active_block_model(self, program: Program = None, include_externals=False):
        model_name = self.active_block_model_name
        if not model_name:
            return None

        try:
            _class = self.models[model_name]
            instance = _class(program=program, include_externals=include_externals)
            return instance
        except KeyError as e:
            print(f"Error: {e}")
            return None

    def get_active_subroutine_model(self, program: Program = None, include_externals=False):
        model_name = self.active_subroutine_model_name
        if not model_name:
            return None

        try:
            _class = self.models[model_name]
            instance = _class(program=program, include_externals=include_externals)
            return instance
        except KeyError as e:
            print(f"Error: {e}")
            return None

    def get_new_model_by_name(self, model_name: str, program: Program = None):
        try:
            _class = self.models[model_name]
            if not program:
                return _class()
            else:
                instance = _class(program=program)
                return instance
        except KeyError as e:
            print(f"Error: {e}")
            return None

    def get_available_model_names(self, model_type):
        result = []
        for name in self.models.keys():
            if issubclass(self.models[name], CodeBlockModel) and (model_type == 1 or model_type == 2):
                result.append(name)
        return result

    def add_listener(self, listener: 'BlockModelServiceListener'):
        self.listeners.append(listener)

    def remove_listener(self, listener: 'BlockModelServiceListener'):
        if listener in self.listeners:
            self.listeners.remove(listener)


class CodeBlockModel:
    pass


def issubclass(_class1: type, _class2: type):
    return isinstance(_class1, type) and issubclass(_class1, _class2)
```

Note that I've used Python's built-in `type` for the model classes.