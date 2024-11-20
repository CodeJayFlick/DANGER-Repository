import numpy as np
from xgboost import DMatrix


class XgbNDManager:
    SYSTEM_MANAGER = None

    def __init__(self):
        if not isinstance(self.SYSTEM_MANAGER, self.__class__):
            self.SYSTEM_MANAGER = self

    @classmethod
    def get_system_manager(cls):
        return cls.SYSTEM_MANAGER

    def allocate_direct(self, capacity: int) -> np.ndarray:
        return np.empty(capacity)

    def from_ndarray(self, array: np.ndarray) -> DMatrix:
        if array is None or isinstance(array, DMatrix):
            return array
        return DMatrix(data=array.tobytes(), shape=tuple(array.shape), label=None)

    def new_sub_manager(self) -> 'XgbNDManager':
        manager = self.__class__()
        return manager

    @property
    def engine(self) -> object:
        return None  # Replace with actual implementation


def create_ndarray(data: np.ndarray, shape: tuple, data_type: str) -> DMatrix:
    if len(shape) != 2:
        raise ValueError("Shape must be in two dimension")
    if data_type.lower() not in ['float32']:
        raise ValueError(f"Only Float32 data type supported, actual {data_type}")
    return DMatrix(data=data.tobytes(), shape=shape, label=None)


def create_csr_ndarray(buffer: np.ndarray, indptr: list, indices: list, shape: tuple) -> DMatrix:
    if len(shape) != 2:
        raise ValueError("Shape must be in two dimension")
    int_indices = [int(i) for i in indices]
    data = buffer.tolist()
    return DMatrix(data=data, index=indptr, column=int_indices)


class SystemManager(XgbNDManager):
    def __init__(self):
        super().__init__()

    # Other methods can be implemented as needed
