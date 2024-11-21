Here is the translation of the Java code into Python:

```Python
class AbstractBlock:
    def __init__(self):
        self.input_shapes = None
        self.input_names = []
        self.version = 1
        self.children = {}
        self.parameters = {}

    @property
    def input_shapes(self):
        return self._input_shapes

    @input_shapes.setter
    def input_shapes(self, value):
        self._input_shapes = value

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, value):
        self._children = value

    @property
    def parameters(self):
        return self._parameters

    @parameters.setter
    def parameters(self, value):
        self._parameters = value

    def forward(self, parameter_store: 'ParameterStore', inputs: list, training: bool, params: dict) -> list:
        if not self.is_initialized():
            self.initialize(parameter_store.get_manager(), DataType.FLOAT32, [x.shape for x in inputs])
        return self.forward_internal(parameter_store, inputs, training, params)

    def forward(self, parameter_store: 'ParameterStore', data: list, labels: list, params: dict) -> list:
        if not self.is_initialized():
            self.initialize(parameter_store.get_manager(), DataType.FLOAT32, [x.shape for x in data])
        return self.forward_internal(parameter_store, data, training=True, params=params)

    def forward_internal(self, parameter_store: 'ParameterStore', inputs: list, training: bool, params: dict) -> list:
        raise NotImplementedError

    def add_child_block(self, name: str, block: object) -> object:
        self.children[name] = block
        return block

    def add_parameter(self, param: object) -> object:
        self.parameters[param.name] = param
        return param

    @property
    def initialized(self):
        if not hasattr(self, '_initialized'):
            self._initialized = False
        return self._initialized

    def initialize(self, manager: 'NDManager', data_type: DataType, input_shapes: list) -> None:
        before_initialize(input_shapes)
        for param in self.parameters.values():
            param.initialize(manager, data_type)
        if not self.initialized:
            prepare(input_shapes)

    @property
    def initialized_child_blocks(self):
        return hasattr(self, '_initialized_child_blocks')

    @initialized_child_blocks.setter
    def initialized_child_blocks(self, value: bool) -> None:
        self._initialized_child_blocks = value

    def before_initialize(self, input_shapes: list) -> None:
        if not self.input_names:
            self.input_names = [f'data{i}' for i in range(len(input_shapes))]
        self.input_shapes = input_shapes

    @property
    def parameters_list(self):
        return list(self.parameters.values())

    def clear(self) -> None:
        for param in self.parameters_list:
            if hasattr(param, 'close'):
                param.close()

    def cast(self, data_type: DataType) -> None:
        raise NotImplementedError

    def save_parameters(self, os: object) -> None:
        os.write_byte(self.version)
        save_metadata(os)

    @property
    def initialized_child_blocks_list(self):
        return list(self.children.values())

    def load_parameters(self, manager: 'NDManager', is: object) -> None:
        self.load_version = is.read_byte()
        if not hasattr(self, '_initialized'):
            read_input_shapes(is)
        for param in self.parameters_list:
            param.load(manager, is)

    @property
    def initialized_child_blocks_dict(self):
        return dict((name, block) for name, block in self.children.items())

    def save_metadata(self, os: object) -> None:
        if not hasattr(self, '_initialized'):
            read_input_shapes(is)
        else:
            save_input_shapes(os)

    @property
    def initialized_child_blocks_dict_list(self):
        return list(self.initialized_child_blocks_dict.values())

    def load_metadata(self, version: int, is: object) -> None:
        if not hasattr(self, '_initialized'):
            read_input_shapes(is)
        else:
            save_input_shapes(os)

    @property
    def initialized_child_blocks_dict_list_list(self):
        return list(self.initialized_child_blocks_dict_list.values())

    def append_shape(self, sb: str, shapes: list) -> None:
        for shape in shapes:
            if not hasattr(shape, 'shape'):
                continue
            long_array = [x.shape[0] for x in shape]
            length = len(long_array)
            if length == 1:
                sb.append(f'({long_array[0]})')
            elif length > 1:
                sb.append('(' + ', '.join(map(str, long_array)) + ')')

    def __str__(self) -> str:
        return f'{self.__class__.__name__}('
```

Please note that this is a direct translation of the Java code into Python.