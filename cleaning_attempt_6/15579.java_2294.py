import uuid
from typing import Any, Optional

class Parameter:
    def __init__(self):
        self.id = str(uuid.uuid4())
        self.name: Optional[str] = None
        self.shape: Optional[tuple[int]] = None
        self.type: type[Any] = object  # Replace with actual type if needed
        self.initializer: Any = None
        self.array: Any = None
        self.requires_grad: bool = True

    def set_name(self, name: str) -> 'Parameter':
        self.name = name
        return self

    def set_shape(self, shape: tuple[int]) -> 'Parameter':
        self.shape = shape
        return self

    def set_type(self, type: Any) -> 'Parameter':
        self.type = type
        return self

    def set_initializer(self, initializer: Any) -> 'Parameter':
        self.initializer = initializer
        return self

    def set_array(self, array: Any) -> 'Parameter':
        self.array = array
        return self

    def requires_gradient(self) -> bool:
        return self.requires_grad

    def is_initialized(self) -> bool:
        return self.array is not None

    def initialize(self, manager, data_type):
        if self.initializer is None or self.shape is None:
            raise ValueError("No initializer and shape set")
        if not self.is_initialized():
            array = self.initializer.initialize(manager, self.shape, data_type)
            array.name = self.name
            if self.requires_grad:
                array.set_requires_gradient(True)

    def save(self, dos):
        if not self.is_initialized():
            dos.write_char('N')
            return
        dos.write_char('P')
        dos.write_byte(1)  # Version number
        dos.write_string(self.name)
        dos.write_array(self.array.encode())

    def load(self, manager, dis):
        magic = dis.read_char()
        if magic == 'N':
            return
        elif magic != 'P':
            raise ValueError("Invalid input data")
        version = dis.read_byte()
        if version != 1:
            raise ValueError(f"Unsupported encoding version: {version}")
        parameter_name = dis.read_string()
        if not self.name or self.name != parameter_name:
            raise ValueError(
                f"Unexpected parameter name: {parameter_name}, expected: {self.name}"
            )
        array = manager.decode(dis)
        shape = array.shape
        return

    def close(self):
        if self.array is not None:
            self.array.close()
            self.array = None


class ParameterBuilder:
    def __init__(self):
        self.name: str = ''
        self.shape: tuple[int] = ()
        self.type: type[Any] = object  # Replace with actual type if needed
        self.initializer: Any = None
        self.array: Any = None
        self.requires_grad: bool = True

    def set_name(self, name: str) -> 'ParameterBuilder':
        self.name = name
        return self

    def set_type(self, type: Any) -> 'ParameterBuilder':
        self.type = type
        return self

    def opt_shape(self, shape: tuple[int]) -> 'ParameterBuilder':
        self.shape = shape
        return self

    def opt_initializer(self, initializer: Any) -> 'ParameterBuilder':
        self.initializer = initializer
        return self

    def opt_array(self, array: Any) -> 'ParameterBuilder':
        self.array = array
        return self

    def set_requires_grad(self, requires_grad: bool) -> 'ParameterBuilder':
        self.requires_grad = requires_grad
        return self

    def build(self) -> Parameter:
        return Parameter()
