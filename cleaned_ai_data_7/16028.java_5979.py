import torch
from typing import List, Dict, Tuple

class IValue:
    def __init__(self, handle: int):
        self.handle = handle

    @property
    def type(self) -> str:
        return PyTorchLibrary.LIB.i_value_get_type(self.handle)

    @property
    def is_tensor(self) -> bool:
        return PyTorchLibrary.LIB.i_value_is_tensor(self.handle)

    @property
    def is_boolean(self) -> bool:
        return PyTorchLibrary.LIB.i_value_is_bool(self.handle)

    @property
    def is_long(self) -> bool:
        return PyTorchLibrary.LIB.i_value_is_long(self.handle)

    @property
    def is_double(self) -> bool:
        return PyTorchLibrary.LIB.i_value_is_double(self.handle)

    @property
    def is_string(self) -> bool:
        return PyTorchLibrary.LIB.i_value_is_string(self.handle)

    @staticmethod
    def from_tensor(value: torch.Tensor) -> 'IValue':
        return IValue(PyTorchLibrary.LIB.i_value_from_tensor(value.handle))

    @staticmethod
    def from_bool(value: bool) -> 'IValue':
        return IValue(PyTorchLibrary.LIB.i_value_from_bool(value))

    @staticmethod
    def from_long(value: int) -> 'IValue':
        return IValue(PyTorchLibrary.LIB.i_value_from_long(value))

    @staticmethod
    def from_double(value: float) -> 'IValue':
        return IValue(PyTorchLibrary.LIB.i_value_from_double(value))

    @staticmethod
    def from_string(value: str) -> 'IValue':
        return IValue(PyTorchLibrary.LIB.i_value_from_string(value))

    @property
    def to_bool(self) -> bool:
        return PyTorchLibrary.LIB.i_value_to_bool(self.handle)

    @property
    def to_long(self) -> int:
        return PyTorchLibrary.LIB.i_value_to_long(self.handle)

    @property
    def to_double(self) -> float:
        return PyTorchLibrary.LIB.i_value_to_double(self.handle)

    @property
    def to_string(self) -> str:
        return PyTorchLibrary.LIB.i_value_to_string(self.handle)

    @staticmethod
    def from_bool_list(list: List[bool]) -> 'IValue':
        handles = [PyTorchLibrary.LIB.i_value_from_bool(b) for b in list]
        return IValue(handles)

    @staticmethod
    def from_long_list(list: List[int]) -> 'IValue':
        handles = [PyTorchLibrary.LIB.i_value_from_long(l) for l in list]
        return IValue(handles)

    @staticmethod
    def from_double_list(list: List[float]) -> 'IValue':
        handles = [PyTorchLibrary.LIB.i_value_from_double(d) for d in list]
        return IValue(handles)

    @property
    def to_bool_array(self) -> List[bool]:
        return PyTorchLibrary.LIB.i_value_to_bool_list(self.handle)

    @property
    def to_long_array(self) -> List[int]:
        return PyTorchLibrary.LIB.i_value_to_long_list(self.handle)

    @property
    def to_double_array(self) -> List[float]:
        return PyTorchLibrary.LIB.i_value_to_double_list(self.handle)

    @staticmethod
    def from_tensor_list(list: List[torch.Tensor]) -> 'IValue':
        handles = [t.handle for t in list]
        return IValue(handles)

    @property
    def to_nd_array(self) -> torch.Tensor:
        return PyTorchLibrary.LIB.i_value_to_tensor(self.handle)

    @staticmethod
    def from_i_value_list(list: List['IValue']) -> 'IValue':
        handles = [iv.handle for iv in list]
        return IValue(handles)

    @property
    def to_nd_array_list(self) -> List[torch.Tensor]:
        if self.is_tensor:
            return [self.to_nd_array()]
        elif self.is_tensor_list:
            return [t for t in PyTorchLibrary.LIB.i_value_to_tensor_list(self.handle)]
        else:
            raise ValueError("Unsupported IValue type.")

    def close(self):
        handle = self.handle
        if handle is not None:
            PyTorchLibrary.LIB.torch_delete_i_value(handle)
