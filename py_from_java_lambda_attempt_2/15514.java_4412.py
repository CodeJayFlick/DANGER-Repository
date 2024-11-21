Here is the translation of the Java code into Python:

```Python
import logging
from abc import ABCMeta, abstractmethod
from typing import Any, Dict, List

class BaseNDManager(metaclass=ABCMeta):
    def __init__(self, parent: 'BaseNDManager', device: str) -> None:
        self.parent = parent
        self.device = device if device else "cpu"
        self.resources = {}
        self.temp_resources = {}
        self.closed = False

    @abstractmethod
    def create(self, data: List[float], shape: tuple) -> Any:
        pass

    @abstractmethod
    def load(self, path: str) -> Any:
        pass

    def default_device(self) -> str:
        return "cpu"

    def zeros(self, shape: tuple, dtype: int) -> Any:
        size = 1
        for dim in shape:
            size *= dim
        buffer = bytearray(size * self.get_dtype_size(dtype))
        return self.create(buffer, shape)

    def ones(self, shape: tuple, dtype: int) -> Any:
        size = 1
        for dim in shape:
            size *= dim
        buffer = bytearray(size * self.get_dtype_size(dtype))
        for i in range(size):
            if dtype == 0x10:  # float16
                buffer[i*2] = Float16Utils.ONE.to_bytes(2, 'little')[0]
            elif dtype == 0x20:  # float32
                buffer[i*4:i*4+4] = (1).to_bytes(4, 'little')
            elif dtype == 0x40:  # float64
                buffer[i*8:i*8+8] = (1.0).to_bytes(8, 'little')
        return self.create(buffer, shape)

    def full(self, shape: tuple, value: float, dtype: int) -> Any:
        raise NotImplementedError

    def arange(self, start: float, stop: float, step: float, dtype: int) -> Any:
        raise NotImplementedError

    def eye(self, rows: int, cols: int, k: int, dtype: int) -> Any:
        raise NotImplementedError

    def linspace(self, start: float, stop: float, num: int, endpoint: bool) -> Any:
        raise NotImplementedError

    def random_integer(self, low: int, high: int, shape: tuple, dtype: int) -> Any:
        raise NotImplementedError

    def random_uniform(self, low: float, high: float, shape: tuple, dtype: int) -> Any:
        raise NotImplementedError

    def random_normal(self, loc: float, scale: float, shape: tuple, dtype: int) -> Any:
        raise NotImplementedError

    def truncated_normal(self, loc: float, scale: float, shape: tuple, dtype: int) -> Any:
        sample_size = 1
        for dim in shape:
            sample_size *= dim
        dist = [0.0] * sample_size
        for i in range(sample_size):
            while True:
                sample = RandomUtils.next_gaussian()
                if abs(sample) < 2:
                    break
            dist[i] = sample
        return self.create(dist, shape)

    def random_multinomial(self, n: int, p_values: Any) -> Any:
        raise NotImplementedError

    def isOpen(self) -> bool:
        return not self.closed

    def getParentManager(self) -> 'BaseNDManager':
        return self.parent

    def newSubManager(self) -> 'BaseNDManager':
        engine = self.get_engine().get_alternative_engine()
        if engine is not None:
            return engine.new_base_manager("cpu")
        return None

    def getDevice(self) -> str:
        return self.device

    def __str__(self) -> str:
        parent_name = "No Parent" if self.parent is None else self.parent.name
        return f"Name: {self.name}, Parent Name: {parent_name}, Opened: {not self.closed}, Resource size: {len(self.resources)}"

    @abstractmethod
    def attachInternal(self, resource_id: str, resource: Any) -> None:
        pass

    @abstractmethod
    def tempAttachInternal(self, original_manager: 'BaseNDManager', resource_id: str, resource: Any) -> None:
        pass

    def detachInternal(self, resource_id: str) -> None:
        if self.closed:
            return
        self.temp_resources.pop(resource_id)
        self.resources.pop(resource_id)

    @abstractmethod
    def invoke(self, operation: str, src: List[Any], dest: List[Any], params: Dict[str, Any]) -> Any:
        pass

    @abstractmethod
    def close(self) -> None:
        if not self.closed:
            for resource in list(self.resources.values()):
                try:
                    resource.close()
                except Exception as e:
                    logging.error("Resource close failed.", e)
            for temp_resource in list(self.temp_resources.values()):
                temp_resource.return_resource()
            parent = self.parent
            if parent is not None and isinstance(parent, BaseNDManager):
                parent.detachInternal(self.uid)

    def debug_dump(self, level: int) -> None:
        sb = "     "
        for _ in range(level):
            sb += "     "
        sb += f"--- NDManager({self.uid[24:]}) resource count: {len(self.resources)}"
        print(sb)
        for c in self.resources.values():
            if isinstance(c, BaseNDManager):
                c.debug_dump(level + 1)

    def get_alternative_manager(self) -> 'BaseNDManager':
        engine = self.get_engine().get_alternative_engine()
        return None if engine is None else engine.new_base_manager("cpu")

    @staticmethod
    def validate_buffer_size(buffer: Any, dtype: int, expected: int) -> None:
        remaining = buffer.remaining()
        expected_size = 1
        for dim in shape:
            expected_size *= dim
        if remaining < expected_size:
            raise ValueError(f"The NDArray size is {expected}, but buffer size is {remaining}")
        if remaining > expected_size:
            logging.warning("Input buffer size is greater than the NDArray size, please set limit explicitly.")
            buffer.limit(expected_size)

    @staticmethod
    def copy_buffer(src: Any, target: bytearray) -> None:
        dtype = DataType.from_buffer(src)
        switcher = {
            0x10: lambda x: [i for i in (Float16Utils.ONE.to_bytes(2, 'little'))],
            0x20: lambda x: [(1).to_bytes(4, 'little')],
            0x40: lambda x: [(1.0).to_bytes(8, 'little')]
        }
        if dtype not in switcher:
            raise AssertionError(f"Unsupported datatype {dtype}")
        for i in range(len(src)):
            target[i] = next(switcher[dtype](src))
```

Please note that this is a translation of the Java code into Python. It may require some adjustments to work correctly, as there are differences between the two languages and their respective standard libraries.